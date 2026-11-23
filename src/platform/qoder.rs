//! Qoder 平台：设备授权（PKCE）/ 令牌续期 / 活动领取（对应 Go 版 qoder.go）。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::store::{Account, Store};
use crate::util::*;

const QODER_WEB: &str = "https://qoder.com.cn";
const QODER_API: &str = "https://openapi.qoder.com.cn";
const QODER_UA: &str = "Qoder";
const QODER_CLIENT_TYPE: &str = "10";
const QODER_LOGIN_TTL: i64 = 900;
const QODER_COOLDOWN: i64 = 30;
const CLIENT_VERSION: &str = "0.4.8";
const MACHINE_OS: &str = "x86_64_win32";
const MACHINE_HOST: &str = "DESKTOP";

const EP_DEVICE_PAGE: &str = "/device/selectAccounts";
const EP_POLL: &str = "/api/v1/deviceToken/poll";
const EP_REFRESH: &str = "/api/v1/deviceToken/refresh";
const EP_CAMPAIGNS: &str = "/sash/api/v1/me/campaigns";

const RECLAIMABLE: &[&str] = &[
    "CLAIMABLE",
    "UNCLAIMED",
    "UN_CLAIMED",
    "AVAILABLE",
    "PENDING_CLAIM",
];
const RECLAIMED: &[&str] = &["CLAIMED", "ALREADY_CLAIMED", "RECEIVED", "GRANTED", "DONE"];
const ACTION_PRIORITY: &[&str] = &["CLAIM_BENEFIT", "VIEW_DETAILS", "DAILY_CHECKIN", "SIGN_IN"];

pub struct Qoder {
    st: Arc<Store>,
}

impl Qoder {
    pub fn new(st: Arc<Store>) -> Self {
        Self { st }
    }

}

fn dur(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn matches_any_ci(s: &str, set: &[&str]) -> bool {
    set.iter().any(|x| s.eq_ignore_ascii_case(x))
}

fn contains_ci(s: &str, needle: &str) -> bool {
    s.to_ascii_uppercase().contains(&needle.to_ascii_uppercase())
}

fn field_str(m: &Map<String, Value>, k: &str) -> String {
    str_v(m.get(k).unwrap_or(&Value::Null)).to_string()
}

/// JS 的 String(v)：字符串原样，其它按 JSON 文本
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// o.benefit.amount ?? o.reward.amount ?? o.credits ?? o.creditAmount（只认非 null）
fn benefit_value(o: &Value) -> Option<Value> {
    let pick = |a: &str, b: &str| o.get(a).and_then(|x| x.get(b)).filter(|v| !v.is_null()).cloned();
    pick("benefit", "amount")
        .or_else(|| pick("reward", "amount"))
        .or_else(|| o.get("credits").filter(|v| !v.is_null()).cloned())
        .or_else(|| o.get("creditAmount").filter(|v| !v.is_null()).cloned())
}

/// JSON 对象的键，最多取前 6 个，用 / 连接
fn keys_digest(v: Option<&Value>) -> String {
    v.and_then(Value::as_object)
        .map(|m| m.keys().take(6).cloned().collect::<Vec<_>>().join("/"))
        .unwrap_or_default()
}

async fn qoder_fetch(
    path: &str,
    method: &str,
    headers: HashMap<String, String>,
    body: Option<Value>,
) -> FetchResult {
    let mut h = HashMap::from([
        ("accept".to_string(), "application/json".to_string()),
        ("accept-language".to_string(), "zh-CN".to_string()),
        ("user-agent".to_string(), QODER_UA.to_string()),
    ]);
    for (k, v) in headers {
        h.insert(k, v);
    }
    let b = if method.eq_ignore_ascii_case("GET") {
        None
    } else {
        body.as_ref().map(json_body)
    };
    fetch(&format!("{}{}", QODER_API, path), method, &h, b, dur(20)).await
}

/// 网络层失败（没有拿到任何 HTTP 响应）
fn net_failed(r: &FetchResult) -> bool {
    r.status == 0
}

fn qoder_auth_headers(at: &str, extra: &HashMap<String, String>) -> HashMap<String, String> {
    let mut h = HashMap::from([
        ("authorization".to_string(), format!("Bearer {}", at)),
        ("cosy-clienttype".to_string(), QODER_CLIENT_TYPE.to_string()),
        ("user-agent".to_string(), QODER_UA.to_string()),
        ("accept".to_string(), "application/json".to_string()),
        ("accept-language".to_string(), "zh-CN".to_string()),
    ]);
    for (k, v) in extra {
        h.insert(k.clone(), v.clone());
    }
    h
}

fn risk_headers(acct: &Map<String, Value>) -> HashMap<String, String> {
    let mut h = HashMap::from([
        ("cosy-version".to_string(), CLIENT_VERSION.to_string()),
        ("cosy-machineos".to_string(), MACHINE_OS.to_string()),
        ("cosy-machinehostname".to_string(), MACHINE_HOST.to_string()),
    ]);
    let mid = str_v(acct.get("machineId").unwrap_or(&Value::Null));
    if !mid.is_empty() {
        h.insert("cosy-machineid".to_string(), mid.to_string());
    }
    h
}

impl Qoder {
    // ---------- 登录 ----------

    /// 设备授权：生成 PKCE 校验串与随机 nonce，返回官网授权页地址。
    pub fn login_start(&self, _body: &Map<String, Value>) -> Result<Value, String> {
        let verifier = random_id(32);
        let challenge = sha256b64url(&verifier);
        let nonce = random_hex(16);
        let machine_id = new_uuid();

        // 参数顺序照抄官网
        let pairs = [
            ("challenge", challenge.as_str()),
            ("challenge_method", "S256"),
            ("machine_id", machine_id.as_str()),
            ("nonce", nonce.as_str()),
        ];
        let parts: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, encode_uri_component(v)))
            .collect();
        let auth_url = format!("{}{}?{}", QODER_WEB, EP_DEVICE_PAGE, parts.join("&"));

        let sess = json!({
            "verifier": verifier,
            "machineId": machine_id,
            "region": "cn",
            "at": now_ms(),
        });
        self.st.set_session(
            "qoder",
            &format!("login:{}", nonce),
            sess.as_object().expect("object"),
            QODER_LOGIN_TTL,
        )?;
        Ok(json!({
            "ok": true,
            "nonce": nonce,
            "region": "cn",
            "regionName": "国内版",
            "authUrl": auth_url,
        }))
    }

    /// 轮询授权结果：202 / 404 表示还没确认，拿到 token 就落库
    pub async fn login_poll(&self, nonce: &str) -> Result<Value, ApiErr> {
        let nonce = nonce.trim();
        if nonce.is_empty() {
            return Err(ApiErr::new(400, "缺少 nonce"));
        }
        let sess = self
            .st
            .get_session("qoder", &format!("login:{}", nonce))
            .ok_or_else(|| ApiErr::new(400, "授权会话已过期，请重新点「添加账号」"))?;
        let query = format!(
            "?nonce={}&verifier={}&challenge_method=S256",
            encode_uri_component(nonce),
            encode_uri_component(&field_str(&sess, "verifier"))
        );
        let h = HashMap::from([
            ("Cosy-Version".to_string(), "1.0.1".to_string()),
            ("Cosy-ClientType".to_string(), "5".to_string()),
            ("user-agent".to_string(), "qoder-local-proxy".to_string()),
        ]);
        let r = qoder_fetch(&format!("{}{}", EP_POLL, query), "GET", h, None).await;

        // 网络失败 ≠ 还没确认：JS 里 fetch 抛错会落到 500
        if net_failed(&r) {
            return Err(ApiErr::new(500, r.text.clone()));
        }
        if r.status == 202 || r.status == 404 {
            return Ok(json!({"status": "pending"}));
        }
        let txt = |keys: &[&str]| -> String {
            keys.iter()
                .map(|k| str_v(r.json.get(*k).unwrap_or(&Value::Null)))
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string()
        };
        if r.status >= 400 {
            let msg = txt(&["errorMessage", "message", "msg"]);
            return Err(ApiErr::new(502, format!("授权轮询失败（HTTP {}）{}", r.status, msg)));
        }

        let data = match r.json.get("data") {
            Some(d) if d.is_object() => d,
            _ => &r.json,
        };
        let tok = |keys: &[&str]| -> String {
            keys.iter()
                .map(|k| str_v(data.get(*k).unwrap_or(&Value::Null)))
                .find(|s| !s.trim().is_empty())
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let token = tok(&["token", "access_token", "device_token"]);
        if token.is_empty() {
            // code != null && code !== 0 && code !== '0'
            if let Some(code) = r.json.get("code").filter(|c| !c.is_null()) {
                let is_zero = match code {
                    Value::Number(n) => n.as_f64() == Some(0.0),
                    Value::String(s) => s == "0",
                    _ => false,
                };
                if !is_zero {
                    return Err(ApiErr::new(
                        502,
                        format!("授权失败（code={}）{}", js_string(code), txt(&["errorMessage", "msg", "message"])),
                    ));
                }
            }
            return Ok(json!({"status": "pending"}));
        }

        let acct = self
            .persist_account(
                &token,
                &tok(&["refresh_token", "refreshToken"]),
                &tok(&["user_id", "userId"]),
                &tok(&["email", "user_email"]),
                &field_str(&sess, "machineId"),
            )
            .map_err(|e| ApiErr::new(500, e))?;
        let _ = self.st.del_session("qoder", &format!("login:{}", nonce));
        Ok(json!({
            "status": "ok",
            "id": acct.get("id").cloned().unwrap_or(Value::Null),
            "label": acct.get("label").cloned().unwrap_or(Value::Null),
            "region": "cn",
        }))
    }

    /// 把一条令牌落成账号记录
    fn persist_account(
        &self,
        access_token: &str,
        refresh_token: &str,
        user_id: &str,
        email: &str,
        machine_id: &str,
    ) -> Result<Value, String> {
        let id = random_id(9);
        // 令牌若是 JWT（3 段），载荷里可能带昵称；只当备注用
        let claims = if access_token.split('.').count() >= 3 { jwt_claims(access_token) } else { None };
        let claim = |k: &str| -> String {
            claims
                .as_ref()
                .and_then(|c| c.get(k))
                .filter(|v| crate::util::js_truthy(v))
                .map(js_string)
                .unwrap_or_default()
        };
        let fallback = format!(
            "Qoder-{}",
            if !user_id.is_empty() { last_n(user_id, 4) } else { truncate_chars(&id, 4) }
        );
        let name = truncate_chars(
            first_non_empty_owned(&[claim("nickname"), claim("name"), claim("email"), email.to_string()]).trim(),
            40,
        );
        let name = if name.is_empty() { fallback } else { name };
        let acct = json!({
            "id": id,
            "label": name,
            "region": "cn",
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "userId": user_id,
            "machineId": machine_id,
            "createdAt": now_ms(),
            "lastState": "new",
            "lastMsg": "授权完成，尚未运行",
            "totalCredit": 0i64,
            "totalSigned": 0i64,
            "cooldownUntil": 0i64,
            "via": "",
        });
        self.st.put("qoder", acct.as_object().expect("object"))?;
        Ok(acct)
    }

    // ---------- 令牌与签到 ----------

    /// refreshToken 会轮换，换到的新令牌写进 d，调用方随后必须落盘。
    async fn refresh_account(&self, d: &mut Map<String, Value>) -> Result<String, TokErr> {
        let rt = field_str(d, "refreshToken").trim().to_string();
        if rt.is_empty() {
            return Err(TokErr::fatal("账号缺少 refreshToken，无法续期，请删掉后重新添加"));
        }
        let h = HashMap::from([
            ("user-agent".to_string(), "qoder-local-proxy".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ]);
        let r = qoder_fetch(EP_REFRESH, "POST", h, Some(json!({"refresh_token": rt}))).await;
        if net_failed(&r) {
            return Err(TokErr::soft(r.text.clone()));
        }
        if r.status == 401 || r.status == 403 {
            return Err(TokErr::fatal("refreshToken 已失效，请删掉后重新添加"));
        }
        if r.status >= 400 {
            return Err(TokErr::soft(format!("令牌续期失败（HTTP {}）", r.status)));
        }
        let data = match r.json.get("data") {
            Some(x) if x.is_object() => x,
            _ => &r.json,
        };
        let get = |keys: &[&str]| -> String {
            keys.iter()
                .map(|k| str_v(data.get(*k).unwrap_or(&Value::Null)))
                .find(|s| !s.trim().is_empty())
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let token = get(&["device_token", "deviceToken", "token", "access_token"]);
        if token.is_empty() {
            return Err(TokErr::soft("续期响应里没有新的 access token"));
        }
        d.insert("accessToken".into(), json!(token));
        let new_rt = get(&["refresh_token", "refreshToken"]);
        if !new_rt.is_empty() {
            d.insert("refreshToken".into(), json!(new_rt));
        }
        d.insert("tokenRefreshedAt".into(), json!(now_ms()));
        Ok(token)
    }

    async fn fetch_campaigns(&self, at: &str, acct: &Map<String, Value>) -> FetchResult {
        let h = qoder_auth_headers(at, &risk_headers(acct));
        qoder_fetch(&format!("{}?forceRefresh=true", EP_CAMPAIGNS), "GET", h, None).await
    }

    async fn claim_campaign(&self, at: &str, campaign_id: &str, acct: &Map<String, Value>) -> FetchResult {
        let mut extra = risk_headers(acct);
        extra.insert("content-type".into(), "application/json".into());
        extra.insert("origin".into(), QODER_API.to_string());
        let h = qoder_auth_headers(at, &extra);
        qoder_fetch(
            &format!("{}/{}/claim", EP_CAMPAIGNS, encode_uri_component(campaign_id)),
            "POST",
            h,
            Some(json!({})),
        )
        .await
    }

    /// 活动列表有的版本包在 data 里，有的直接在顶层
    fn campaign_rows(payload: &Value) -> Vec<Value> {
        payload
            .get("campaigns")
            .filter(|v| !v.is_null())
            .or_else(|| payload.get("data").and_then(|d| d.get("campaigns")))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn action_rank(t: &str) -> usize {
        ACTION_PRIORITY.iter().position(|p| *p == t).unwrap_or(ACTION_PRIORITY.len())
    }

    /// 一行活动压成一句话，用于诊断
    fn describe_row(row: &Value) -> String {
        let s_or = |k: &str, dflt: &str| -> String {
            match row.get(k) {
                None | Some(Value::Null) => dflt.to_string(),
                Some(v) => js_string(v),
            }
        };
        let typ = s_or("actionType", "空");
        let st = s_or("claimStatus", "空");
        let title = ["title", "name", "campaignName", "displayName"]
            .iter()
            .map(|k| row.get(*k).filter(|v| js_truthy(v)).map(js_string).unwrap_or_default())
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        let title = title.trim().to_string();
        let amt = benefit_value(row).map(|v| num_of(&v)).unwrap_or(0.0);
        let mut s = format!("{} / {}", typ, st);
        if !title.is_empty() {
            s.push_str(&format!("「{}」", truncate_chars(&title, 12)));
        }
        if amt != 0.0 {
            s.push_str(&format!(" +{}", num_text(amt)));
        }
        s
    }

    /// 把「为什么没领到」说清楚：一共几条、都是些什么活动
    fn digest_campaigns(payload: &Value) -> String {
        let rows = Self::campaign_rows(payload);
        if rows.is_empty() {
            let keys = if payload.is_object() { keys_digest(Some(payload)) } else { "非对象".to_string() };
            let data_keys = keys_digest(payload.get("data"));
            return format!(
                "返回 0 条活动，顶层字段 {}{}",
                if keys.is_empty() { "空".to_string() } else { keys },
                if data_keys.is_empty() { String::new() } else { format!("，data 字段 {}", data_keys) }
            );
        }
        let mut parts: Vec<String> = Vec::new();
        for row in &rows {
            let k = Self::describe_row(row);
            if !parts.contains(&k) {
                parts.push(k);
            }
        }
        parts.truncate(4);
        let text = format!("返回 {} 条：{}", rows.len(), parts.join("，"));
        if text.chars().count() > 150 {
            format!("{}…", truncate_chars(&text, 148))
        } else {
            text
        }
    }

    /// 写入失败态并落盘，返回统一的结果
    fn finish(&self, d: &mut Map<String, Value>, base: Map<String, Value>) -> Value {
        let state = d.get("lastState").cloned().unwrap_or(Value::Null);
        let msg = d.get("lastMsg").cloned().unwrap_or(Value::Null);
        let _ = self.st.put("qoder", d);
        merged(base, json!({"state": state, "msg": msg}))
    }

    pub async fn signin_one(&self, a: &Account, force: bool) -> Value {
        let mut d = a.data.clone();
        let now = now_ms();
        let today = bj_day(now);
        let base = json!({"id": a.id, "label": field_str(&d, "label")})
            .as_object()
            .cloned()
            .unwrap_or_default();

        // 只有「我们真的领到了」才允许当天跳过后续轮次；
        // already 不算，因为官方可能在 10:00 后才补发新活动，得让它再查一次。
        if !force && field_str(&d, "lastOkDate") == today && field_str(&d, "lastState") == "checked" {
            return merged(base, json!({"state": "skipped", "msg": "今日已完成"}));
        }
        if !force && to_i64(d.get("cooldownUntil").unwrap_or(&Value::Null)) > now {
            return merged(base, json!({"state": "skipped", "msg": "限流冷却中"}));
        }

        // 拿令牌 + 拉活动列表；任一环节抛错按 fatal 与否落成 token_dead / error
        let mut at = field_str(&d, "accessToken");
        let step: Result<FetchResult, TokErr> = async {
            if at.is_empty() {
                at = self.refresh_account(&mut d).await?;
            }
            let mut list = self.fetch_campaigns(&at, &d).await;
            if net_failed(&list) {
                return Err(TokErr::soft(list.text.clone()));
            }
            if (list.status == 401 || list.status == 403) && !field_str(&d, "refreshToken").is_empty() {
                at = self.refresh_account(&mut d).await?;
                list = self.fetch_campaigns(&at, &d).await;
                if net_failed(&list) {
                    return Err(TokErr::soft(list.text.clone()));
                }
            }
            Ok(list)
        }
        .await;
        let list = match step {
            Ok(l) => l,
            Err(e) => {
                d.insert("lastState".into(), json!(if e.fatal { "token_dead" } else { "error" }));
                d.insert("lastMsg".into(), json!(e.msg));
                d.insert("lastRun".into(), json!(now));
                return self.finish(&mut d, base);
            }
        };

        // 用局部变量判断这次的结果，别沿用上一次运行留下的 lastState
        let mut failed = "";
        if list.status == 429 {
            d.insert("cooldownUntil".into(), json!(now + QODER_COOLDOWN * 60000));
            failed = "error";
            d.insert(
                "lastMsg".into(),
                json!(format!("请求过于频繁（HTTP 429），{} 分钟后重试", QODER_COOLDOWN)),
            );
        } else if list.status == 401 || list.status == 403 {
            failed = "token_dead";
            d.insert("lastMsg".into(), json!("凭证已失效，请删掉这个账号重新添加"));
        } else if list.status != 200 {
            failed = "error";
            d.insert("lastMsg".into(), json!(format!("活动列表返回 HTTP {}", list.status)));
        }
        if !failed.is_empty() {
            d.insert("lastState".into(), json!(failed));
            d.insert("lastRun".into(), json!(now));
            return self.finish(&mut d, base);
        }

        let rows = Self::campaign_rows(&list.json);
        let row_status = |row: &Value| row.get("claimStatus").map(js_string).unwrap_or_default();
        let is_obj = |row: &&Value| row.is_object();
        // 不按 actionType 硬过滤：只认 CLAIM_BENEFIT 会把其它类型整排跳过，连「已领」都判不出来。
        let claimed = rows
            .iter()
            .filter(is_obj)
            .any(|row| matches_any_ci(&row_status(row), RECLAIMED));
        // 先按状态挑出可领项，再按优先级稳定排序取第一条；campaignId 缺失是「目标有问题」，不是「跳过它」
        let mut cands: Vec<&Value> = rows
            .iter()
            .filter(is_obj)
            .filter(|row| matches_any_ci(&row_status(row), RECLAIMABLE))
            .collect();
        cands.sort_by_key(|row| Self::action_rank(&field_of(row, "actionType")));
        let target = cands.first().copied();

        d.insert("lastRun".into(), json!(now));

        let target = match target {
            Some(t) => t,
            None => {
                let digest = Self::digest_campaigns(&list.json);
                // 绝不把营销卡的 CLAIMED 当成「今天已签」，否则会显示已签、实际一个 credits 都没拿到。
                let has_benefit = rows
                    .iter()
                    .any(|row| contains_ci(&field_of(row, "actionType"), "CLAIM_BENEFIT"));
                if claimed {
                    if has_benefit {
                        d.insert("lastState".into(), json!("already"));
                        d.insert("lastOkDate".into(), json!(today));
                        d.insert("lastMsg".into(), json!("今日已领取（活动状态已是 CLAIMED）"));
                    } else {
                        d.insert("lastState".into(), json!("wait"));
                        d.insert("lastMsg".into(), json!(format!("今日没有签到活动，只有营销活动 · {}", digest)));
                    }
                } else {
                    d.insert("lastState".into(), json!("wait"));
                    d.insert("lastMsg".into(), json!(format!("没有可领取的活动 · {}", digest)));
                }
                return self.finish(&mut d, base);
            }
        };

        let campaign_id = ["campaignId", "campaignKey", "key", "id"]
            .iter()
            .map(|k| target.get(*k).filter(|v| js_truthy(v)).map(js_string).unwrap_or_default())
            .find(|s| !s.is_empty())
            .unwrap_or_default()
            .trim()
            .to_string();
        if campaign_id.is_empty() {
            d.insert("lastState".into(), json!("error"));
            d.insert("lastMsg".into(), json!("活动数据里没有 campaignId，无法领取"));
            return self.finish(&mut d, base);
        }

        let claim = self.claim_campaign(&at, &campaign_id, &d).await;
        if net_failed(&claim) {
            d.insert("lastState".into(), json!("error"));
            d.insert("lastMsg".into(), json!(format!("领取请求异常：{}", claim.text)));
            return self.finish(&mut d, base);
        }
        let empty = json!({});
        let body = if claim.json.is_object() { &claim.json } else { &empty };
        let already = claim.status == 409
            || body.get("result").and_then(Value::as_str) == Some("ALREADY_CLAIMED")
            || body.get("replayed") == Some(&Value::Bool(true));

        if already {
            d.insert("lastState".into(), json!("already"));
            d.insert("lastOkDate".into(), json!(today));
            d.insert("lastMsg".into(), json!("今日已领取"));
        } else if claim.status == 200 || claim.status == 201 {
            // 金额：先看领取响应，再回落到活动行
            let amount = num_of(
                &benefit_value(body)
                    .or_else(|| benefit_value(target))
                    .unwrap_or(json!(0)),
            );
            let action_type = field_of(target, "actionType");
            let type_tag = if action_type != "CLAIM_BENEFIT" {
                format!("（{}）", if action_type.is_empty() { "未知类型".to_string() } else { action_type })
            } else {
                String::new()
            };
            let status_v = body.get("status").filter(|v| js_truthy(v));
            if let Some(sv) = status_v.filter(|v| v.as_str() != Some("CLAIMED")) {
                d.insert("lastState".into(), json!("pending"));
                d.insert(
                    "lastMsg".into(),
                    json!(format!("提交成功但上游未确认（状态 {}）", js_string(sv))),
                );
            } else {
                d.insert("lastState".into(), json!("checked"));
                d.insert("lastOkDate".into(), json!(today));
                d.insert("lastCredit".into(), num_value(amount));
                let tc = num_of(d.get("totalCredit").unwrap_or(&Value::Null)) + amount;
                d.insert("totalCredit".into(), num_value(tc));
                let ts = num_of(d.get("totalSigned").unwrap_or(&Value::Null)) + 1.0;
                d.insert("totalSigned".into(), num_value(ts));
                d.insert(
                    "lastMsg".into(),
                    json!(format!("领取成功 +{} credits{}", num_text(amount), type_tag)),
                );
            }
        } else if claim.status == 429 {
            d.insert("lastState".into(), json!("error"));
            d.insert("cooldownUntil".into(), json!(now + QODER_COOLDOWN * 60000));
            d.insert("lastMsg".into(), json!("领取被限流（HTTP 429），稍后重试"));
        } else if claim.status == 401 || claim.status == 403 {
            d.insert("lastState".into(), json!("token_dead"));
            d.insert("lastMsg".into(), json!("领取失败，凭证已失效，请重新添加账号"));
        } else {
            d.insert("lastState".into(), json!("error"));
            // 只认非空字符串；数值型 code 不拼进去（否则会拼出 "null" 之类）
            let why = ["message", "errorMessage", "msg", "result", "code"]
                .iter()
                .filter_map(|k| body.get(*k).and_then(Value::as_str))
                .find(|s| !s.trim().is_empty())
                .unwrap_or("")
                .to_string();
            d.insert("lastMsg".into(), json!(format!("领取失败（HTTP {}）{}", claim.status, why)));
        }
        self.finish(&mut d, base)
    }

    // ---------- 管理 ----------

    pub fn list(&self) -> Value {
        let list = self.st.list("qoder").unwrap_or_default();
        let mut out = Vec::new();
        let now = now_ms();
        let today = bj_day(now);
        for a in &list {
            let d = &a.data;
            let last_run_ms = to_i64(d.get("lastRun").unwrap_or(&Value::Null));
            let cooldown = to_i64(d.get("cooldownUntil").unwrap_or(&Value::Null));
            let ok_date = field_str(d, "lastOkDate");
            let nn = |k: &str| d.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null);
            let or_zero = |k: &str| d.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(json!(0));
            out.push(json!({
                "id": a.id,
                "label": field_str(d, "label"),
                "region": "cn",
                "regionName": "国内版",
                "lastState": nn("lastState"),
                "lastMsg": nn("lastMsg"),
                "lastRun": if last_run_ms > 0 { json!(bj_string(last_run_ms)) } else { Value::Null },
                "lastOkDate": if ok_date.is_empty() { Value::Null } else { json!(ok_date) },
                "lastCredit": nn("lastCredit"),
                "totalCredit": or_zero("totalCredit"),
                "totalSigned": or_zero("totalSigned"),
                "cooldownUntil": if cooldown > now { cooldown } else { 0 },
                "today": today,
                "signedToday": ok_date == today,
                "ranToday": last_run_ms > 0 && bj_day(last_run_ms) == today,
                "via": field_str(d, "via"),
                // 令牌永不下发
            }));
        }
        json!({"count": out.len(), "today": today, "accounts": out})
    }

    pub async fn run_all(&self, force: bool) -> Value {
        let list = self.st.list("qoder").unwrap_or_default();
        let mut results = Vec::new();
        for a in &list {
            results.push(self.signin_one(a, force).await);
        }
        json!({"at": bj_string(now_ms()), "count": results.len(), "results": results})
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        self.st.remove("qoder", id)
    }

    pub fn rename(&self, id: &str, label: &str) -> Result<(), String> {
        let mut a = self
            .st
            .get("qoder", id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "账号不存在".to_string())?;
        a.data.insert("label".into(), json!(label));
        self.st.put("qoder", &a.data)
    }
}

/// row[k] 按字符串取（缺失为空串）
fn field_of(row: &Value, k: &str) -> String {
    match row.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(v) => js_string(v),
    }
}

fn last_n(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_string()
    } else {
        chars[chars.len() - n..].iter().collect()
    }
}
