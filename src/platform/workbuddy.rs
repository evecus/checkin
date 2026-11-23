//! WorkBuddy 平台：微信扫码授权 / 令牌轮换 / 签到（对应 JS 版 WorkBuddy 模块）。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::store::{Account, Store};
use crate::util::*;

const WB_API: &str = "https://copilot.tencent.com";
const WB_UA: &str = "workbuddy-signin-worker/1.0";
const WB_LOGIN_TTL: i64 = 900;

pub struct WorkBuddy {
    st: Arc<Store>,
}

impl WorkBuddy {
    pub fn new(st: Arc<Store>) -> Self {
        Self { st }
    }
}

fn dur(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

/// 对应 JS wbFetch：响应不是 JSON 就当错误抛出（而不是当成空对象继续往下走）。
async fn wb_fetch(
    path: &str,
    method: &str,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
) -> Result<FetchResult, String> {
    let mut h = HashMap::new();
    h.insert("Content-Type".to_string(), "application/json".to_string());
    h.insert("User-Agent".to_string(), WB_UA.to_string());
    for (k, v) in headers {
        h.insert(k, v);
    }
    let b = if method.eq_ignore_ascii_case("GET") {
        None
    } else {
        body.or_else(|| Some(b"{}".to_vec()))
    };
    let r = fetch(&format!("{}{}", WB_API, path), method, &h, b, dur(20)).await;
    if !r.is_json {
        return Err(format!(
            "响应不是 JSON (HTTP {}): {}",
            r.status,
            truncate_chars(&r.text, 120)
        ));
    }
    Ok(r)
}

fn wb_no_auth_headers() -> HashMap<String, String> {
    HashMap::from([
        ("X-No-Authorization".to_string(), "true".to_string()),
        ("X-No-User-Id".to_string(), "true".to_string()),
        ("X-No-Enterprise-Id".to_string(), "true".to_string()),
        ("X-No-Department-Info".to_string(), "true".to_string()),
        ("X-Domain".to_string(), "copilot.tencent.com".to_string()),
    ])
}

fn wb_auth_header(at: &str) -> HashMap<String, String> {
    HashMap::from([("Authorization".to_string(), format!("Bearer {}", at))])
}

fn msg_of(j: &Value) -> String {
    match j.get("msg") {
        None | Some(Value::Null) => String::new(),
        Some(v) => value_display(v),
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn field_str(m: &Map<String, Value>, k: &str) -> String {
    str_v(m.get(k).unwrap_or(&Value::Null)).to_string()
}

struct Tokens {
    access: String,
    refresh: String,
}

/// 单次签到请求的结果
struct CheckinRes {
    state: &'static str, // checked | already | error
    credit: f64,
    code: String,
    msg: String,
}

impl WorkBuddy {
    // ---------- 登录 ----------

    /// 扫码登录第一步：向服务端申请一个登录态。
    pub async fn login_start(&self, _body: &Map<String, Value>) -> Result<Value, String> {
        let r = wb_fetch(
            "/v2/plugin/auth/state?platform=workbuddy",
            "POST",
            wb_no_auth_headers(),
            Some(b"{}".to_vec()),
        )
        .await?;
        let state = r
            .json
            .get("data")
            .and_then(|d| d.get("state"))
            .map(str_v)
            .unwrap_or("")
            .to_string();
        if json_code(&r.json) != Some(0) || state.is_empty() {
            return Err(format!(
                "申请登录态失败 code={} {} (HTTP {})",
                code_disp(json_code(&r.json)),
                msg_of(&r.json),
                r.status
            ));
        }
        let auth_url = r.json["data"].get("authUrl").cloned().unwrap_or(Value::Null);
        // 记一下 state 是我们发出去的，避免有人拿别人的 state 来轮询
        let sess = json!({"at": now_ms()});
        self.st.set_session(
            "wb",
            &format!("login:{}", state),
            sess.as_object().expect("object"),
            WB_LOGIN_TTL,
        )?;
        Ok(json!({"ok": true, "state": state, "authUrl": auth_url}))
    }

    /// 轮询授权结果，拿到令牌就顺手存成账号
    pub async fn login_poll(&self, state: &str) -> Result<Value, ApiErr> {
        let state = state.trim();
        if state.is_empty() {
            return Err(ApiErr::new(400, "缺少 state"));
        }
        if self.st.get_session("wb", &format!("login:{}", state)).is_none() {
            return Err(ApiErr::new(400, "登录会话已过期，请重新获取二维码"));
        }
        let r = wb_fetch(
            &format!("/v2/plugin/auth/token?state={}", encode_uri_component(state)),
            "GET",
            wb_no_auth_headers(),
            None,
        )
        .await
        .map_err(|e| ApiErr::new(500, e))?;

        let code = json_code(&r.json);
        if code == Some(11217) {
            return Ok(json!({"status": "pending"}));
        }
        let data = r.json.get("data").and_then(Value::as_object);
        let access = data.map(|d| field_str(d, "accessToken")).unwrap_or_default();
        if code != Some(0) || access.is_empty() {
            return Err(ApiErr::new(
                500,
                format!(
                    "轮询登录结果失败 code={} {} (HTTP {})",
                    code_disp(code),
                    msg_of(&r.json),
                    r.status
                ),
            ));
        }
        let rt = data.map(|d| field_str(d, "refreshToken")).unwrap_or_default().trim().to_string();
        if rt.is_empty() {
            return Err(ApiErr::new(502, "登录成功但服务端没返回 refreshToken"));
        }
        let acct = self
            .persist_account(&rt, &access, "")
            .await
            .map_err(|e| ApiErr::new(500, e))?;
        let _ = self.st.del_session("wb", &format!("login:{}", state));
        Ok(json!({
            "status": "ok",
            "id": acct.get("id").cloned().unwrap_or(Value::Null),
            "label": acct.get("label").cloned().unwrap_or(Value::Null),
        }))
    }

    async fn persist_account(
        &self,
        refresh_token: &str,
        access_token: &str,
        label: &str,
    ) -> Result<Value, String> {
        let id = random_id(9);
        let mut name = truncate_chars(label.trim(), 40);
        if name.is_empty() && !access_token.is_empty() {
            name = self.fetch_nickname(access_token).await;
        }
        if name.is_empty() {
            name = format!("账号-{}", truncate_chars(&id, 4));
        }
        let acct = json!({
            "id": id,
            "label": name,
            "refreshToken": refresh_token,
            "createdAt": now_ms(),
            "lastState": "new",
            "lastMsg": "尚未运行",
            "verified": true,
            "tokenRefreshedAt": now_ms(),
        });
        self.st.put("wb", acct.as_object().expect("object"))?;
        Ok(acct)
    }

    /// 尽量取一个昵称当备注名，取不到就算了，不影响登录
    async fn fetch_nickname(&self, at: &str) -> String {
        let mut h = wb_auth_header(at);
        h.insert("X-Domain".to_string(), "copilot.tencent.com".to_string());
        let r = match wb_fetch("/v2/accounts", "GET", h, None).await {
            Ok(r) => r,
            Err(_) => return String::new(),
        };
        let data = r.json.get("data");
        // data.accounts ?? data
        let list = data
            .and_then(|d| d.get("accounts"))
            .filter(|v| !v.is_null())
            .or(data);
        let first = match list.and_then(Value::as_array).and_then(|a| a.first()) {
            Some(f) => f,
            None => return String::new(),
        };
        // nickname ?? nickName
        let nick = first
            .get("nickname")
            .filter(|v| !v.is_null())
            .or_else(|| first.get("nickName"))
            .map(value_display)
            .unwrap_or_default();
        nick.trim().to_string()
    }

    // ---------- 令牌与签到 ----------

    /// 用 refresh_token 换新的双令牌。refreshToken 会轮换，调用方必须立刻保存新的。
    /// 返回 fatal=true 表示令牌链断了（需要人工重新登录）；网络/非 JSON 属于临时错误。
    async fn refresh_tokens(&self, refresh_token: &str) -> Result<Tokens, TokErr> {
        let h = HashMap::from([
            ("X-Refresh-Token".to_string(), refresh_token.to_string()),
            ("X-Auth-Refresh-Source".to_string(), "plugin".to_string()),
            ("X-Domain".to_string(), "copilot.tencent.com".to_string()),
        ]);
        let r = wb_fetch("/v2/plugin/auth/token/refresh", "POST", h, Some(b"{}".to_vec()))
            .await
            .map_err(TokErr::soft)?;
        let data = r.json.get("data").filter(|d| js_truthy(d));
        if json_code(&r.json) != Some(0) || data.is_none() {
            return Err(TokErr::fatal(format!(
                "刷新令牌失败 code={} {} (HTTP {})",
                code_disp(json_code(&r.json)),
                msg_of(&r.json),
                r.status
            )));
        }
        let d = data.and_then(Value::as_object).cloned().unwrap_or_default();
        let mut nrt = field_str(&d, "refreshToken");
        if nrt.is_empty() {
            nrt = refresh_token.to_string();
        }
        Ok(Tokens { access: field_str(&d, "accessToken"), refresh: nrt })
    }

    async fn checkin_status(&self, at: &str) -> Option<Map<String, Value>> {
        let r = wb_fetch(
            "/v2/billing/meter/checkin-activity-status",
            "POST",
            wb_auth_header(at),
            Some(b"{}".to_vec()),
        )
        .await
        .ok()?;
        if json_code(&r.json) != Some(0) {
            return None;
        }
        r.json.get("data").and_then(Value::as_object).cloned()
    }

    async fn do_checkin(&self, at: &str) -> Result<CheckinRes, String> {
        let r = wb_fetch(
            "/v2/billing/meter/daily-checkin",
            "POST",
            wb_auth_header(at),
            Some(b"{}".to_vec()),
        )
        .await?;
        let code = json_code(&r.json);
        if code == Some(0) {
            let credit = match r.json.get("data").and_then(|d| d.get("credit")).filter(|v| !v.is_null()) {
                Some(c) => num_of(c),
                None => 100.0,
            };
            return Ok(CheckinRes { state: "checked", credit, code: "0".into(), msg: String::new() });
        }
        if code == Some(10001) {
            return Ok(CheckinRes { state: "already", credit: 0.0, code: "10001".into(), msg: String::new() });
        }
        Ok(CheckinRes {
            state: "error",
            credit: 0.0,
            code: code_disp(code),
            msg: msg_of(&r.json),
        })
    }

    pub async fn signin_one(&self, a: &Account, force: bool) -> Value {
        let mut d = a.data.clone();
        let now = now_ms();
        let today = bj_day(now);
        let base = json!({"id": a.id, "label": field_str(&d, "label")})
            .as_object()
            .cloned()
            .unwrap_or_default();

        // 今天已成功过、且没要求强制，直接跳过（省一次请求，也避免无谓刷新）
        if !force && field_str(&d, "lastOkDate") == today && field_str(&d, "lastState") != "error" {
            return merged(base, json!({"state": "skipped", "msg": "今日已完成"}));
        }

        let rt = field_str(&d, "refreshToken");
        let tokens = match self.refresh_tokens(&rt).await {
            Ok(t) => t,
            Err(e) => {
                let state = if e.fatal { "token_dead" } else { "error" };
                d.insert("lastState".into(), json!(state));
                d.insert("lastMsg".into(), json!(e.msg));
                d.insert("lastRun".into(), json!(now));
                let _ = self.st.put("wb", &d);
                return merged(base, json!({"state": state, "msg": e.msg}));
            }
        };
        // 先落新令牌。哪怕后面签到失败，令牌链也不能断。
        d.insert("refreshToken".into(), json!(tokens.refresh));
        d.insert("tokenRefreshedAt".into(), json!(now));

        let mut result = match self.do_checkin(&tokens.access).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("签到请求异常: {}", e);
                d.insert("lastState".into(), json!("error"));
                d.insert("lastMsg".into(), json!(msg));
                d.insert("lastRun".into(), json!(now));
                let _ = self.st.put("wb", &d);
                return merged(base, json!({"state": "error", "msg": msg}));
            }
        };

        let mut streak = Value::Null;
        let mut total = Value::Null;
        // 状态查询失败不影响主流程
        if let Some(st) = self.checkin_status(&tokens.access).await {
            streak = st.get("streak_days").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null);
            total = st.get("total_credits").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null);
            // 顺手把服务端视图对上，判断是否真的已签
            if st.get("checked_in_today") == Some(&Value::Bool(true)) && result.state == "error" {
                result = CheckinRes { state: "already", credit: 0.0, code: "10001".into(), msg: String::new() };
            }
        }

        d.insert("lastRun".into(), json!(now));
        d.insert("streak".into(), streak.clone());
        d.insert("total".into(), total.clone());

        if result.state == "error" {
            d.insert("lastState".into(), json!("error"));
            d.insert(
                "lastMsg".into(),
                json!(format!("签到失败 code={} {}", result.code, result.msg)),
            );
        } else {
            d.insert("lastState".into(), json!(result.state));
            let msg = if result.state == "checked" {
                format!("+{} 积分", num_text(result.credit))
            } else {
                "今日已签".to_string()
            };
            d.insert("lastMsg".into(), json!(msg));
            d.insert("lastOkDate".into(), json!(today));
            if result.state == "checked" {
                d.insert("lastCredit".into(), num_value(result.credit));
                let n = num_of(d.get("totalSigned").unwrap_or(&Value::Null)) + 1.0;
                d.insert("totalSigned".into(), num_value(n));
            }
        }
        let _ = self.st.put("wb", &d);
        merged(
            base,
            json!({
                "state": d.get("lastState").cloned().unwrap_or(Value::Null),
                "msg": d.get("lastMsg").cloned().unwrap_or(Value::Null),
                "streak": streak,
                "total": total,
            }),
        )
    }

    // ---------- 管理 ----------

    pub fn list(&self) -> Value {
        let list = self.st.list("wb").unwrap_or_default();
        let mut out = Vec::new();
        for a in &list {
            let d = &a.data;
            let last_run_ms = to_i64(d.get("lastRun").unwrap_or(&Value::Null));
            let ok_date = field_str(d, "lastOkDate");
            let nn = |k: &str| d.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null);
            out.push(json!({
                "id": a.id,
                "label": field_str(d, "label"),
                "lastState": nn("lastState"),
                "lastMsg": nn("lastMsg"),
                "lastRun": if last_run_ms > 0 { json!(bj_string(last_run_ms)) } else { Value::Null },
                "lastOkDate": if ok_date.is_empty() { Value::Null } else { json!(ok_date) },
                "streak": nn("streak"),
                "total": nn("total"),
                "totalSigned": d.get("totalSigned").filter(|v| !v.is_null()).cloned().unwrap_or(json!(0)),
                // 永远不返回令牌，连指纹都不给
            }));
        }
        json!({"count": out.len(), "accounts": out})
    }

    pub async fn run_all(&self, force: bool) -> Value {
        let list = self.st.list("wb").unwrap_or_default();
        let mut results = Vec::new();
        for a in &list {
            results.push(self.signin_one(a, force).await);
        }
        let count = |f: &dyn Fn(&str) -> bool| {
            results
                .iter()
                .filter(|r| f(r.get("state").map(str_v).unwrap_or("")))
                .count()
        };
        json!({
            "at": bj_string(now_ms()),
            "accounts": results.len(),
            "checked": count(&|s| s == "checked"),
            "already": count(&|s| s == "already" || s == "skipped"),
            "failed": count(&|s| s == "error" || s == "token_dead"),
            "results": results,
        })
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        self.st.remove("wb", id)
    }

    pub fn rename(&self, id: &str, label: &str) -> Result<(), String> {
        let mut a = self
            .st
            .get("wb", id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "账号不存在".to_string())?;
        a.data.insert("label".into(), json!(label));
        self.st.put("wb", &a.data)
    }
}
