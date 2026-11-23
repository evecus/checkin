//! Trae 平台：设备身份 / 扫码授权 / ECDSA 设备签名 / 签到（对应 Go 版 trae.go）。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use url::Url;

use crate::store::{Account, Store};
use crate::util::*;

const TRAE_API: &str = "https://api.trae.cn";
const TRAE_UA: &str = "Trae/1.107.1";
const IDE_VERSION: &str = "1.107.1";
const CLIENT_IDE: &str = "ono9krqynydwx5";
const CLIENT_OLD: &str = "en1oxy7wnw8j9n";
const OAUTH_APP_ID: &str = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8";
const OAUTH_APP_VER: &str = "3.3.100";
const OAUTH_PLUGIN: &str = "2.3.83560";
const AUTHORIZE_BASE: &str = "https://www.trae.cn";
const CALLBACK_LOCAL: &str = "http://127.0.0.1:17388/authorize";
const REQ_BODY: &str = r#"{"req_source": 1}"#;

const EP_CLAIM: &str = "/trae/api/v2/ug/checkin_credits/claim";
const EP_STATUS: &str = "/trae/api/v2/ug/checkin_credits/status";
const EP_ENTITLE: &str = "/trae/api/v2/pay/user_current_entitlement_list";
const EP_EXCHANGE: &str = "/trae/api/v3/oauth/ExchangeToken";
const EP_EXCHANGE_LEGACY: &str =
    "https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken";

const CODE_OK: i64 = 0;
const CODE_ALREADY: i64 = 9095;
const CODE_RATE: i64 = 9074;
const LOGIN_TTL: i64 = 900;
const AUTH_FAIL_CODES: [i64; 4] = [1001, 1002, 401, 403];
const COOLDOWN_MIN: i64 = 55;
const PEAK_COOLDOWN_MIN: i64 = 12;

pub struct Trae {
    st: Arc<Store>,
}

impl Trae {
    pub fn new(st: Arc<Store>) -> Self {
        Self { st }
    }
}

fn dur(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn value_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => v.to_string(),
    }
}

fn trunc_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

async fn trae_fetch(
    path: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body: Option<Vec<u8>>,
) -> FetchResult {
    let full = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("{}{}", TRAE_API, path)
    };
    let mut h = headers.clone();
    h.insert("Content-Type".to_string(), "application/json".to_string());
    let b = if method.eq_ignore_ascii_case("GET") {
        None
    } else {
        body
    };
    fetch(&full, method, &h, b, dur(20)).await
}

fn ug_headers(token: &str, acct: &Map<String, Value>) -> HashMap<String, String> {
    let field = |k: &str| str_v(acct.get(k).unwrap_or(&Value::Null)).trim().to_string();
    let mut h = HashMap::from([
        ("Authorization".to_string(), format!("Cloud-IDE-JWT {}", token)),
        ("X-User-Region".to_string(), "CN".to_string()),
        ("User-Agent".to_string(), TRAE_UA.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("x-app-version".to_string(), IDE_VERSION.to_string()),
    ]);
    // 缺设备头会被服务端拒成 9074；deviceType / osVersion 以账号记录为准，缺省才回落默认值
    let did = field("deviceId");
    if !did.is_empty() {
        h.insert("x-device-id".to_string(), did);
    }
    h.insert(
        "x-device-type".to_string(),
        first_non_empty(&[&str_v(acct.get("deviceType").unwrap_or(&Value::Null)).to_string(), "Windows"]).to_string(),
    );
    h.insert(
        "x-os-version".to_string(),
        first_non_empty(&[&str_v(acct.get("osVersion").unwrap_or(&Value::Null)).to_string(), "10.0.19045"]).to_string(),
    );
    let brand = field("deviceBrand");
    if !brand.is_empty() {
        h.insert("x-device-brand".to_string(), brand);
    }
    h
}

/// JS：encodeURIComponent(v).replace(/%2F/g, '/')（空格是 %20，不是 +）
fn qs_quote(v: &str) -> String {
    encode_uri_component(v).replace("%2F", "/")
}

fn build_authorize_url(o: &HashMap<String, String>) -> String {
    let get = |k: &str| o.get(k).map(String::as_str).unwrap_or("");
    let params: Vec<(&str, String)> = vec![
        ("login_version", "1".to_string()),
        ("auth_from", get("authFrom").to_string()),
        ("login_channel", "native_ide".to_string()),
        ("plugin_version", OAUTH_PLUGIN.to_string()),
        ("auth_type", "local".to_string()),
        ("client_id", get("clientId").to_string()),
        ("redirect", "0".to_string()),
        ("login_trace_id", get("trace").to_string()),
        ("auth_callback_url", get("callback").to_string()),
        ("machine_id", get("machineId").to_string()),
        ("device_id", get("deviceId").to_string()),
        ("x_device_id", get("deviceId").to_string()),
        ("x_machine_id", get("machineId").to_string()),
        ("x_device_brand", "PC".to_string()),
        ("x_device_type", "Windows".to_string()),
        ("x_os_version", "10.0.19045".to_string()),
        ("x_env", String::new()),
        ("x_app_version", OAUTH_APP_VER.to_string()),
        ("x_app_type", "stable".to_string()),
        ("code_challenge", get("challenge").to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("channel_name", "common".to_string()),
    ];
    let parts: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, qs_quote(v)))
        .collect();
    format!("{}/authorization?{}", AUTHORIZE_BASE, parts.join("&"))
}

fn merge_headers(a: &HashMap<String, String>, b: &HashMap<String, String>) -> HashMap<String, String> {
    let mut m = a.clone();
    for (k, v) in b {
        m.insert(k.clone(), v.clone());
    }
    m
}


/// 回调参数（对应 JS parseCallbackParams，各字段均已 trim）
#[derive(Default, Debug)]
struct CallbackParams {
    auth_code: String,
    refresh_token: String,
    trace: String,
    host: String,
    name: String,
    uid: String,
    #[allow(dead_code)]
    error: String,
}

/// 兑换/刷新接口的错误描述：code=.. msg (HTTP ..)
fn describe_exchange_err(j: &Value, text: &str, status: i32) -> String {
    let err = j
        .get("ResponseMetadata")
        .and_then(|m| m.get("Error"))
        .filter(|e| e.is_object())
        .or_else(|| j.get("error").filter(|e| e.is_object()));
    let get = |k: &str| err.and_then(|e| e.get(k)).filter(|v| !v.is_null());
    let code = get("Code")
        .or_else(|| j.get("code").filter(|v| !v.is_null()))
        .map(value_display)
        .unwrap_or_else(|| "?".to_string());
    let msg_data = err
        .and_then(|e| e.get("Data"))
        .and_then(|d| d.get("__Message.error"))
        .map(str_v)
        .unwrap_or("");
    let msg = [
        msg_data,
        get("Message").map(str_v).unwrap_or(""),
        str_v(j.get("message").unwrap_or(&Value::Null)),
        str_v(j.get("msg").unwrap_or(&Value::Null)),
    ]
    .into_iter()
    .find(|s| !s.is_empty())
    .map(|s| s.to_string())
    .unwrap_or_else(|| trunc_chars(text, 160));
    format!("code={} {} (HTTP {})", code, msg, status)
}

/// 时间辅助：Math.ceil((until - now) / 60000)
fn ceil_minutes(until: i64, now: i64) -> i64 {
    (until - now + 59_999) / 60_000
}

fn field_str(m: &Map<String, Value>, k: &str) -> String {
    str_v(m.get(k).unwrap_or(&Value::Null)).to_string()
}

/// 单次签到请求的结果（code=-1 表示响应里没有 code；code_disp 用于展示）
struct ClaimRes {
    status: i32,
    code: i64,
    code_disp: String,
    msg: String,
    points: Value,
}

/// 状态查询结果
struct StatusRes {
    ok: bool,
    checked: bool,
    credits: Option<f64>,
}

impl Trae {
    // ---------- 登录 ----------

    pub fn login_start(&self, _body: &Map<String, Value>) -> Result<Value, String> {
        let (priv_pem, pub_pem) = gen_device_identity()?;
        let device_id = gen_device_id();
        let machine_id = random_hex(16);
        let (verifier, challenge) = pkce_pair();
        let trace = random_hex(8);

        let o = HashMap::from([
            ("authFrom".to_string(), "trae".to_string()),
            ("clientId".to_string(), CLIENT_IDE.to_string()),
            ("trace".to_string(), trace.clone()),
            ("callback".to_string(), CALLBACK_LOCAL.to_string()),
            ("deviceId".to_string(), device_id.clone()),
            ("machineId".to_string(), machine_id.clone()),
            ("challenge".to_string(), challenge),
        ]);
        let auth_url = build_authorize_url(&o);

        let sess = json!({
            "trace": trace,
            "line": "trae",
            "verifier": verifier,
            "callback": CALLBACK_LOCAL,
            "deviceId": device_id,
            "machineId": machine_id,
            "privateKeyPem": priv_pem,
            "publicKeyPem": pub_pem,
            "clientId": CLIENT_IDE,
            "platform": "IDE_PC",
            "status": "pending",
            "createdAt": now_ms(),
        });
        self.put_login_session(sess.as_object().expect("object"))?;

        Ok(json!({
            "ok": true,
            "trace": trace,
            "authUrl": auth_url,
            "callback": CALLBACK_LOCAL,
            "deviceId": device_id,
            "line": "trae",
            "label": "Trae",
        }))
    }

    /// 写登录会话，并记最新 trace（供只带 authCode 没有 trace 的回调兜底）
    fn put_login_session(&self, sess: &Map<String, Value>) -> Result<(), String> {
        let trace = field_str(sess, "trace");
        self.st
            .set_session("trae", &format!("login:{}", trace), sess, LOGIN_TTL)?;
        let latest = json!({"trace": trace});
        self.st
            .set_session("trae", "login:latest", latest.as_object().expect("object"), LOGIN_TTL)
    }

    fn parse_callback_params(u: &Url) -> CallbackParams {
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        let get = |k: &str| -> String { q.get(k).map(|s| s.trim().to_string()).unwrap_or_default() };
        let mut auth_code = String::new();
        if let Some(raw) = q.get("authCodeInfo").filter(|s| !s.is_empty()) {
            if let Ok(j) = serde_json::from_str::<Value>(raw) {
                auth_code = value_display_or_empty(j.get("AuthCode")).trim().to_string();
            }
        }
        if auth_code.is_empty() {
            auth_code = first_non_empty(&[&get("code"), &get("AuthCode")]).to_string();
        }
        let mut refresh_token = String::new();
        for k in ["refreshToken", "refresh_token", "RefreshToken"] {
            let v = get(k).trim_matches('"').to_string();
            if !v.is_empty() {
                refresh_token = v;
                break;
            }
        }
        CallbackParams {
            auth_code,
            refresh_token,
            trace: first_non_empty(&[&get("loginTraceID"), &get("login_trace_id"), &get("state")]).to_string(),
            host: get("host"),
            name: first_non_empty(&[&get("name"), &get("nickname"), &get("userName")]).to_string(),
            uid: get("uid"),
            error: get("error"),
        }
    }

    fn host_base(h: &str) -> String {
        let s = h.trim();
        if s.is_empty() {
            return TRAE_API.to_string();
        }
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            s.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", s.trim_end_matches('/'))
        }
    }

    /// AuthCode → 双令牌：主端点 DeviceInfo → 备用端点 AuthCode → 备用端点 Code
    async fn exchange_auth_code(
        p: &CallbackParams,
        sess: &Map<String, Value>,
    ) -> Result<(String, String, String, String), String> {
        let sv = |k: &str| -> Value { sess.get(k).cloned().unwrap_or(Value::Null) };
        let device_id = field_str(sess, "deviceId");
        let dev = json!({
            "DeviceID": device_id, "MachineID": field_str(sess, "machineId"),
            "PlatformCode": sv("platform"), "DeviceType": "PC", "DeviceName": "PC",
            "DeviceModel": "", "ClientVersion": OAUTH_APP_VER,
            "DevicePublicKey": field_str(sess, "publicKeyPem"), "DeviceBrand": "", "DeviceCPU": "",
            "OSInfo": "Windows", "OSVersion": "10.0.19045",
        });
        let platform = field_str(sess, "platform");
        let base_headers = HashMap::from([
            ("Accept".to_string(), "*/*".to_string()),
            ("User-Agent".to_string(), format!("Trae/{}", OAUTH_APP_VER)),
            ("x-device-id".to_string(), device_id.clone()),
            ("x-app-id".to_string(), OAUTH_APP_ID.to_string()),
            ("x-platform-code".to_string(), platform.clone()),
        ]);
        let client_id = field_str(sess, "clientId");
        let auth_code = &p.auth_code;
        let verifier = field_str(sess, "verifier");

        let variants: Vec<(&str, String, HashMap<String, String>, Value)> = vec![
            (
                "DeviceInfo",
                format!("{}{}", Self::host_base(&p.host), EP_EXCHANGE),
                merge_headers(
                    &base_headers,
                    &HashMap::from([("x-cloudide-token".to_string(), String::new())]),
                ),
                json!({
                    "ClientID": client_id, "AuthCode": auth_code, "CodeVerifier": verifier,
                    "DeviceInfo": dev, "IDEVersion": OAUTH_APP_VER,
                }),
            ),
            (
                "AuthCode",
                EP_EXCHANGE_LEGACY.to_string(),
                base_headers.clone(),
                json!({
                    "ClientID": client_id, "AuthCode": auth_code, "CodeVerifier": verifier,
                    "DeviceID": device_id, "PlatformCode": platform,
                }),
            ),
            (
                "Code",
                EP_EXCHANGE_LEGACY.to_string(),
                base_headers.clone(),
                json!({
                    "ClientID": client_id, "Code": auth_code, "CodeVerifier": verifier,
                    "DeviceID": device_id, "PlatformCode": platform,
                }),
            ),
        ];

        let mut errs: Vec<String> = Vec::new();
        for (tag, url, headers, body) in variants {
            let r = trae_fetch(&url, "POST", &headers, Some(json_body(&body))).await;
            let rt = find_refresh(&r.json);
            let at = find_access(&r.json);
            if !rt.is_empty() {
                // 兑换响应偶尔带用户资料，能拿到昵称就直接当备注
                let mut name = pick_nickname(&r.json, 0);
                if name.is_empty() {
                    name = nickname_from_jwt(&at);
                }
                return Ok((rt, at, tag.to_string(), name));
            }
            let desc = if r.status == 0 {
                format!("网络错误: {}", trunc_chars(&r.text, 160))
            } else {
                describe_exchange_err(&r.json, &r.text, r.status)
            };
            if !at.is_empty() {
                errs.push(format!("{}: 响应只有 AccessToken，没有 RefreshToken（无法续期）{}", tag, desc));
            } else {
                errs.push(format!("{}: {}", tag, desc));
            }
        }
        Err(format!("登录失败 → {}", errs.join(" | ")))
    }

    /// 完成一次登录：换取令牌 → 落库 → 回写会话状态
    async fn complete_login(
        &self,
        sess: &mut Map<String, Value>,
        p: &CallbackParams,
    ) -> Result<Value, String> {
        if field_str(sess, "status") == "ok" {
            return Ok(json!({
                "ok": true,
                "label": sess.get("label").cloned().unwrap_or(Value::Null),
                "id": sess.get("accountId").cloned().unwrap_or(Value::Null),
                "repeat": true,
            }));
        }
        let mut refresh_token = p.refresh_token.clone();
        let mut via = "callback".to_string();
        // 昵称来源：回调参数 → 令牌载荷 → 兑换响应，取到第一个算数
        let mut nick = first_non_empty(&[&p.name, &nickname_from_jwt(&p.refresh_token)]).to_string();
        if refresh_token.is_empty() {
            if p.auth_code.is_empty() {
                return Err("回调里既没有 AuthCode 也没有 refreshToken".to_string());
            }
            let (rt, _, tag, name) = Self::exchange_auth_code(p, sess).await?;
            refresh_token = rt;
            via = tag;
            if nick.is_empty() {
                nick = name;
            }
        }
        let refresh_token = refresh_token.trim().to_string();
        if refresh_token.is_empty() {
            return Err("登录响应里没有 refreshToken".to_string());
        }

        // 都拿不到就回落到设备后缀，用户可在控制台点「备注」自己改
        let device_id = field_str(sess, "deviceId");
        let tail: String = {
            let cs: Vec<char> = device_id.chars().collect();
            cs[cs.len().saturating_sub(4)..].iter().collect()
        };
        let mut label = trunc_chars(first_non_empty(&[nick.trim(), p.uid.trim()]), 40);
        if label.is_empty() {
            label = format!("Trae-{}", tail);
        }
        let acct = json!({
            "id": random_id(9),
            "label": label,
            "refreshToken": refresh_token,
            "deviceId": device_id,
            "machineId": field_str(sess, "machineId"),
            "privateKeyPem": field_str(sess, "privateKeyPem"),
            "publicKeyPem": field_str(sess, "publicKeyPem"),
            "deviceName": "PC",
            "deviceModel": "",
            "deviceBrand": "",
            "deviceType": "Windows",
            "osInfo": "Windows",
            "osVersion": "10.0.19045",
            "clientId": field_str(sess, "clientId"),
            "platformCode": field_str(sess, "platform"),
            "source": "scan",
            "createdAt": now_ms(),
            "lastState": "new",
            "lastMsg": "扫码登录，尚未运行",
            "cooldownUntil": 0i64,
        });
        let acct_map = acct.as_object().expect("object");
        self.st.put("trae", acct_map)?;
        sess.insert("status".into(), json!("ok"));
        sess.insert("label".into(), json!(label));
        sess.insert("accountId".into(), acct.get("id").cloned().unwrap_or(Value::Null));
        sess.insert("via".into(), json!(via));
        sess.insert("error".into(), json!(""));
        let _ = self.put_login_session(sess);
        Ok(json!({
            "ok": true,
            "label": label,
            "id": acct.get("id").cloned().unwrap_or(Value::Null),
            "via": via,
        }))
    }

    pub async fn login_claim(&self, raw_url: &str) -> Result<Value, ApiErr> {
        let text = raw_url.trim();
        if text.is_empty() {
            return Err(ApiErr::new(400, "请粘贴回调地址"));
        }
        let u = match Url::parse(text) {
            // new URL(text) 只在带协议时成功；没协议（含 127.0.0.1:端口/...）走下面的兜底
            Ok(u) if text.contains("://") => u,
            _ => {
                let tail = if text.starts_with('?') {
                    text.to_string()
                } else {
                    text.trim_start_matches(['?', '/']).to_string()
                };
                Url::parse(&format!("https://placeholder.local/{}", tail))
                    .map_err(|_| ApiErr::new(400, "这不像是回调地址"))?
            }
        };
        let p = Self::parse_callback_params(&u);
        if p.auth_code.is_empty() && p.refresh_token.is_empty() {
            return Err(ApiErr::new(
                400,
                "地址里没找到 authCodeInfo / code，请复制完整地址（含 ? 之后的部分）",
            ));
        }
        let mut trace = p.trace.clone();
        if trace.is_empty() {
            if let Some(s) = self.st.get_session("trae", "login:latest") {
                trace = field_str(&s, "trace");
            }
        }
        if trace.is_empty() {
            return Err(ApiErr::new(400, "没有待完成的登录会话，请先点「添加账号」"));
        }
        let mut sess = self
            .st
            .get_session("trae", &format!("login:{}", trace))
            .ok_or_else(|| ApiErr::new(400, "登录会话已过期，请重新发起"))?;
        match self.complete_login(&mut sess, &p).await {
            Ok(v) => Ok(v),
            Err(e) => {
                // 失败要落在会话上，轮询才看得到原因
                sess.insert("status".into(), json!("error"));
                sess.insert("error".into(), json!(e));
                let _ = self.put_login_session(&sess);
                Err(ApiErr::new(502, e))
            }
        }
    }

    pub fn login_poll(&self, trace: &str) -> Result<Value, ApiErr> {
        let trace = trace.trim();
        if trace.is_empty() {
            return Err(ApiErr::new(400, "缺少 trace"));
        }
        let sess = match self.st.get_session("trae", &format!("login:{}", trace)) {
            Some(s) => s,
            None => return Ok(json!({"status": "expired"})),
        };
        let status = field_str(&sess, "status");
        Ok(json!({
            "status": if status.is_empty() { "pending".to_string() } else { status },
            "label": field_str(&sess, "label"),
            "error": field_str(&sess, "error"),
            "accountId": field_str(&sess, "accountId"),
            "via": field_str(&sess, "via"),
        }))
    }

    // ---------- 令牌与签到 ----------

    fn explain_refresh_err(j: &Value, text: &str) -> String {
        let err = j
            .get("ResponseMetadata")
            .and_then(|m| m.get("Error"))
            .and_then(Value::as_object);
        let code = err.and_then(|e| e.get("Code")).filter(|v| !v.is_null());
        let mut msg = err
            .and_then(|e| e.get("Data"))
            .and_then(|d| d.get("__Message.error"))
            .map(str_v)
            .unwrap_or("")
            .to_string();
        if msg.is_empty() {
            msg = err.and_then(|e| e.get("Message")).map(str_v).unwrap_or("").to_string();
        }
        if msg.is_empty() {
            msg = trunc_chars(text, 200);
        }
        let code_s = code.map(value_display).unwrap_or_else(|| "?".to_string());
        let hint = match code_s.as_str() {
            "20101" => "refreshToken 已失效或被别处轮换，请删掉该账号重新扫码登录",
            "10101" => "refreshToken 与当前产品线不匹配，请用对应按钮重新扫码登录",
            "20405" => "服务端要求设备证明，但该账号缺少设备密钥，请删掉后重新扫码登录",
            "20403" => "设备密钥与令牌不匹配，请删掉该账号重新扫码登录",
            _ => "",
        };
        if hint.is_empty() {
            format!("code={} {}", code_s, msg)
        } else {
            format!("code={} {}（{}）", code_s, msg, hint)
        }
    }

    /// 用 refreshToken 换新的双令牌。注意要传「当前」账号数据，别传陈旧快照：
    /// 首次刷新后 refreshToken 已轮换，再用旧值会被服务端判失效。
    async fn refresh_tokens(&self, d: &Map<String, Value>) -> Result<(String, String), String> {
        let rt = str_v(d.get("refreshToken").unwrap_or(&Value::Null)).trim().to_string();
        if rt.is_empty() {
            return Err("账号没有 refreshToken".to_string());
        }
        let has_keys = !str_v(d.get("privateKeyPem").unwrap_or(&Value::Null)).is_empty()
            && !str_v(d.get("publicKeyPem").unwrap_or(&Value::Null)).is_empty();
        if !has_keys {
            let body = json!({
                "ClientID": CLIENT_OLD, "RefreshToken": rt, "ClientSecret": "-", "UserID": "",
            });
            let h = HashMap::from([
                ("Accept".to_string(), "application/json".to_string()),
                ("User-Agent".to_string(), TRAE_UA.to_string()),
            ]);
            let r = trae_fetch(EP_EXCHANGE_LEGACY, "POST", &h, Some(json_body(&body))).await;
            let result = r.json.get("Result").and_then(Value::as_object);
            let token = result
                .and_then(|x| x.get("Token"))
                .map(str_v)
                .unwrap_or("")
                .to_string();
            if r.status >= 400 || token.is_empty() {
                return Err(format!(
                    "刷新令牌失败: {}",
                    Self::explain_refresh_err(&r.json, &r.text)
                ));
            }
            let mut nrt = result
                .and_then(|x| x.get("RefreshToken"))
                .map(str_v)
                .unwrap_or("")
                .to_string();
            if nrt.is_empty() {
                nrt = rt;
            }
            return Ok((token, nrt));
        }

        let combos = [
            (
                first_non_empty(&[str_v(d.get("clientId").unwrap_or(&Value::Null)), CLIENT_IDE]).to_string(),
                first_non_empty(&[str_v(d.get("platformCode").unwrap_or(&Value::Null)), "IDE_PC"]).to_string(),
            ),
            (CLIENT_OLD.to_string(), "IDE_PC".to_string()),
            (CLIENT_OLD.to_string(), "SOLO_PC".to_string()),
        ];
        let mut seen: HashSet<String> = HashSet::new();
        let mut last_err = String::new();
        let dstr = |k: &str| str_v(d.get(k).unwrap_or(&Value::Null)).to_string();
        for (client_id, platform) in combos {
            if !seen.insert(format!("{}|{}", client_id, platform)) {
                continue;
            }
            let ts = chrono::Utc::now().timestamp();
            let nonce = random_hex(16);
            let canonical = format!("POST\n{}\n{}\n{}\n{}\n{}", EP_EXCHANGE, client_id, rt, ts, nonce);
            let signature = ec_sign(&dstr("privateKeyPem"), canonical.as_bytes())
                .map_err(|e| format!("设备签名失败（检查设备私钥）: {}", e))?;
            let proof = json!({"Timestamp": ts, "Nonce": nonce, "Signature": signature});
            // 字符串字段一律落成字符串（缺失为 ""），不能发 null
            let info = json!({
                "DeviceID": dstr("deviceId"),
                "MachineID": dstr("machineId"),
                "PlatformCode": platform,
                "DeviceType": "PC",
                "DeviceName": first_non_empty(&[&dstr("deviceName"), "PC"]),
                "DeviceModel": dstr("deviceModel"),
                "ClientVersion": IDE_VERSION,
                "DevicePublicKey": dstr("publicKeyPem"),
                "DeviceBrand": dstr("deviceBrand"),
                "DeviceCPU": "",
                "OSInfo": first_non_empty(&[&dstr("osInfo"), "Windows"]),
                "OSVersion": first_non_empty(&[&dstr("osVersion"), "10.0.19045"]),
            });
            let body = json!({
                "ClientID": client_id, "ClientSecret": "", "RefreshToken": rt,
                "DeviceInfo": info, "DeviceProof": proof, "IDEVersion": IDE_VERSION,
            });
            let h = HashMap::from([("x-cloudide-token".to_string(), String::new())]);
            let r = trae_fetch(EP_EXCHANGE, "POST", &h, Some(json_body(&body))).await;
            let result = r.json.get("Result").and_then(Value::as_object);
            let token = result
                .and_then(|x| x.get("Token"))
                .map(str_v)
                .unwrap_or("")
                .to_string();
            if r.status < 400 && !token.is_empty() {
                let mut nrt = result
                    .and_then(|x| x.get("RefreshToken"))
                    .map(str_v)
                    .unwrap_or("")
                    .to_string();
                if nrt.is_empty() {
                    nrt = rt;
                }
                return Ok((token, nrt));
            }
            last_err = Self::explain_refresh_err(&r.json, &r.text);
            // 只有「不匹配」类错误才值得换一组钥匙，其它错误直接抛
            if !r.text.contains("10101") && !r.text.contains("20403") {
                break;
            }
        }
        Err(format!(
            "刷新令牌失败: {}",
            if last_err.is_empty() { "未知错误".to_string() } else { last_err }
        ))
    }

    /// 提交签到：0 成功 / 9095 今日已签 / 9074 限流
    async fn claim(&self, token: &str, acct: &Map<String, Value>) -> ClaimRes {
        let h = ug_headers(token, acct);
        let r = trae_fetch(EP_CLAIM, "POST", &h, Some(REQ_BODY.as_bytes().to_vec())).await;
        if !r.is_json {
            // 非 JSON（网关错误页、网络失败）绝不能当成 code=0
            return ClaimRes {
                status: r.status,
                code: -1,
                code_disp: "?".to_string(),
                msg: trunc_chars(&r.text, 160),
                points: Value::Null,
            };
        }
        let code_v = r.json.get("code").filter(|v| !v.is_null());
        let code = code_v.map(to_i64).unwrap_or(-1);
        let mut msg = str_v(r.json.get("message").unwrap_or(&Value::Null)).to_string();
        if msg.is_empty() {
            msg = trunc_chars(&r.text, 160);
        }
        let points = r
            .json
            .get("data")
            .and_then(Value::as_object)
            .and_then(|d| d.get("points"))
            .cloned()
            .unwrap_or(Value::Null);
        ClaimRes {
            status: r.status,
            code,
            code_disp: code_v.map(value_display).unwrap_or_else(|| "-1".to_string()),
            msg,
            points,
        }
    }

    /// 查询今日签到状态：checked_in / credits
    async fn status_of(&self, token: &str, acct: &Map<String, Value>) -> StatusRes {
        let h = ug_headers(token, acct);
        let r = trae_fetch(EP_STATUS, "POST", &h, Some(REQ_BODY.as_bytes().to_vec())).await;
        if !r.is_json || r.status >= 400 {
            return StatusRes { ok: false, checked: false, credits: None };
        }
        StatusRes {
            ok: true,
            checked: r.json.get("checked_in") == Some(&Value::Bool(true)),
            credits: r.json.get("credits").and_then(Value::as_f64),
        }
    }

    /// 查积分余额：优先 usage_summary，再按 entitlement 包求和兜底
    async fn credits_of(&self, token: &str, acct: &Map<String, Value>) -> Option<f64> {
        let h = ug_headers(token, acct);
        let r = trae_fetch(EP_ENTITLE, "POST", &h, Some(br#"{"require_usage": true}"#.to_vec())).await;
        if !r.is_json {
            return None;
        }
        let root = match r.json.get("data").filter(|d| js_truthy(d)) {
            Some(d) => d,
            None => &r.json,
        };
        let us = root.get("usage_summary");
        let total = us.and_then(|u| u.get("total_amount")).map(num_of).unwrap_or(0.0);
        let used = us.and_then(|u| u.get("consumed_amount")).map(num_of).unwrap_or(0.0);
        if total > 0.0 {
            return Some(total - used);
        }
        let mut sum = 0.0f64;
        let mut found = false;
        if let Some(packs) = root.get("user_entitlement_pack_list").and_then(Value::as_array) {
            for p in packs {
                let limit = p
                    .get("entitlement_base_info")
                    .and_then(|b| b.get("quota"))
                    .and_then(|q| q.get("credits_limit"))
                    .map(num_of)
                    .unwrap_or(0.0);
                let consumed = p
                    .get("usage")
                    .and_then(|u| u.get("credits_amount"))
                    .map(num_of)
                    .unwrap_or(0.0);
                if limit > 0.0 {
                    found = true;
                    sum += (limit - consumed).max(0.0);
                }
            }
        }
        if found { Some(sum) } else { None }
    }

    /// 早窗（北京时间 0 点）冷却更短，好让下一轮还能在窗口里补签
    fn cooldown_minutes() -> i64 {
        if bj_hour(now_ms()) == 0 { PEAK_COOLDOWN_MIN } else { COOLDOWN_MIN }
    }

    /// 刷新令牌并把结果写进 d（令牌链不能断，调用方随后落盘）
    async fn rotate(&self, d: &mut Map<String, Value>, now: i64, stamp: bool) -> Result<String, String> {
        let (token, nrt) = self.refresh_tokens(d).await?;
        d.insert("refreshToken".into(), json!(nrt));
        d.insert("accessToken".into(), json!(token));
        d.insert("accessExp".into(), json!(jwt_exp(&token)));
        if stamp {
            d.insert("tokenRefreshedAt".into(), json!(now));
        }
        Ok(token)
    }

    pub async fn signin_one(&self, a: &Account, force: bool) -> Value {
        let mut d = a.data.clone();
        let now = now_ms();
        let today = bj_day(now);
        let base = json!({"id": a.id, "label": field_str(&d, "label")})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let cooldown_until = to_i64(d.get("cooldownUntil").unwrap_or(&Value::Null));

        if !force && cooldown_until > now {
            return merged(
                base,
                json!({"state": "cooldown", "msg": format!("限流冷却中，约 {} 分钟", ceil_minutes(cooldown_until, now))}),
            );
        }
        if !force && field_str(&d, "lastOkDate") == today {
            return merged(base, json!({"state": "skipped", "msg": "今日已完成"}));
        }

        // 1) 拿一个可用的 accessToken：还没过期就直接用，避免无谓轮换
        let mut token = field_str(&d, "accessToken");
        let exp = jwt_exp(&token);
        let usable = !token.is_empty() && (exp == 0 || exp * 1000 - now > 120000);
        if !usable {
            match self.rotate(&mut d, now, true).await {
                Ok(t) => {
                    token = t;
                    let _ = self.st.put("trae", &d); // 先落盘：令牌链不能断
                }
                Err(e) => return self.token_dead(&mut d, base, now, e),
            }
        }

        // 2) 提交签到（鉴权类错误刷新一次再试）
        let mut res = self.claim(&token, &d).await;
        if AUTH_FAIL_CODES.contains(&res.code) {
            match self.rotate(&mut d, now, false).await {
                Ok(t) => {
                    token = t;
                    let _ = self.st.put("trae", &d);
                    res = self.claim(&token, &d).await;
                }
                Err(e) => return self.token_dead(&mut d, base, now, e),
            }
        }

        d.insert("lastRun".into(), json!(now));

        // 3) 限流：换个假设备号也没用，9074 会原样返回，按账号冷却等下轮
        if res.code == CODE_RATE || res.status == 429 || res.status >= 500 {
            let mins = Self::cooldown_minutes();
            let msg = format!("限流 9074，冷却 {} 分钟", mins);
            d.insert("cooldownUntil".into(), json!(now + mins * 60000));
            d.insert("lastState".into(), json!("rate"));
            d.insert("lastMsg".into(), json!(msg));
            let _ = self.st.put("trae", &d);
            return merged(base, json!({"state": "rate", "msg": msg}));
        }

        // 4) 今日已签
        if res.code == CODE_ALREADY {
            d.insert("lastState".into(), json!("already"));
            d.insert("lastMsg".into(), json!("今日已签"));
            d.insert("lastOkDate".into(), json!(today));
            d.insert("cooldownUntil".into(), json!(0i64));
            let st = self.status_of(&token, &d).await;
            if st.ok {
                // st.credits ?? acct.credits：回查没给数就保留旧值，不能覆盖成 null
                if let Some(c) = st.credits {
                    d.insert("credits".into(), num_value(c));
                }
                d.insert("checkedIn".into(), json!(true));
            }
            let _ = self.st.put("trae", &d);
            return merged(
                base,
                json!({"state": "already", "msg": "今日已签", "credits": d.get("credits").cloned().unwrap_or(Value::Null)}),
            );
        }

        // 5) 其它失败
        if res.code != CODE_OK {
            let text = format!("签到失败 code={} {}", res.code_disp, res.msg).trim().to_string();
            d.insert("lastState".into(), json!("error"));
            d.insert("lastMsg".into(), json!(text));
            let _ = self.st.put("trae", &d);
            return merged(base, json!({"state": "error", "msg": text}));
        }

        // 6) code=0 未必真到账：用同一 deviceId 回查 checked_in 是否翻转
        let st = self.status_of(&token, &d).await;
        let confirmed = st.ok && st.checked;
        let st_credits = if st.ok { st.credits } else { None };

        // bal ?? credits ?? acct.credits ?? null
        let bal = self.credits_of(&token, &d).await.or(st_credits);
        if let Some(b) = bal {
            d.insert("credits".into(), num_value(b));
        }

        if !confirmed {
            d.insert("lastState".into(), json!("pending"));
            d.insert("lastMsg".into(), json!("已提交，但回查未确认，等下轮再试"));
            d.insert("cooldownUntil".into(), json!(now + 12 * 60000));
            let _ = self.st.put("trae", &d);
            return merged(
                base,
                json!({
                    "state": "pending",
                    "msg": "已提交，但回查未确认，等下轮再试",
                    "credits": d.get("credits").cloned().unwrap_or(Value::Null),
                }),
            );
        }

        let msg2 = if js_truthy(&res.points) {
            format!("+{} 积分", value_display(&res.points))
        } else {
            "签到成功".to_string()
        };
        d.insert("lastState".into(), json!("checked"));
        d.insert("lastMsg".into(), json!(msg2));
        d.insert("lastOkDate".into(), json!(today));
        d.insert("lastCredit".into(), res.points.clone());
        let total_credit = num_of(d.get("totalCredit").unwrap_or(&Value::Null)) + num_of(&res.points);
        d.insert("totalCredit".into(), num_value(total_credit));
        let total_signed = num_of(d.get("totalSigned").unwrap_or(&Value::Null)) + 1.0;
        d.insert("totalSigned".into(), num_value(total_signed));
        d.insert("checkedIn".into(), json!(true));
        d.insert("cooldownUntil".into(), json!(0i64));
        let _ = self.st.put("trae", &d);
        merged(
            base,
            json!({
                "state": "checked", "msg": msg2,
                "credits": d.get("credits").cloned().unwrap_or(Value::Null),
                "points": res.points,
            }),
        )
    }

    fn token_dead(&self, d: &mut Map<String, Value>, base: Map<String, Value>, now: i64, e: String) -> Value {
        d.insert("lastState".into(), json!("token_dead"));
        d.insert("lastMsg".into(), json!(e));
        d.insert("lastRun".into(), json!(now));
        let _ = self.st.put("trae", d);
        merged(base, json!({"state": "token_dead", "msg": e}))
    }

    // ---------- 管理 ----------

    pub fn list(&self) -> Value {
        let list = self.st.list("trae").unwrap_or_default();
        let mut out = Vec::new();
        let now = now_ms();
        let today = bj_day(now);
        for a in &list {
            let d = &a.data;
            // 只有数值型积分才下发，保留两位小数（Math.round(x*100)/100）
            let credits = match d.get("credits") {
                Some(Value::Number(n)) => num_value((n.as_f64().unwrap_or(0.0) * 100.0).round() / 100.0),
                _ => Value::Null,
            };
            let last_run_ms = to_i64(d.get("lastRun").unwrap_or(&Value::Null));
            let cooldown = to_i64(d.get("cooldownUntil").unwrap_or(&Value::Null));
            let ok_date = field_str(d, "lastOkDate");
            let or_zero = |k: &str| d.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(json!(0));
            out.push(json!({
                "id": a.id,
                "label": field_str(d, "label"),
                "lastState": d.get("lastState").cloned().unwrap_or(Value::Null),
                "lastMsg": d.get("lastMsg").cloned().unwrap_or(Value::Null),
                "lastRun": if last_run_ms > 0 { json!(bj_string(last_run_ms)) } else { Value::Null },
                "lastOkDate": if ok_date.is_empty() { Value::Null } else { json!(ok_date) },
                "lastCredit": d.get("lastCredit").cloned().unwrap_or(Value::Null),
                "credits": credits,
                "totalCredit": or_zero("totalCredit"),
                "totalSigned": or_zero("totalSigned"),
                "cooldownUntil": if cooldown > now { cooldown } else { 0 },
                "hasKeys": !field_str(d, "privateKeyPem").is_empty() && !field_str(d, "publicKeyPem").is_empty(),
                "hasDevice": !field_str(d, "deviceId").trim().is_empty(),
                // 服务端当场判定，避免前端拿历史状态跨天残留
                "today": today,
                "signedToday": ok_date == today,
                "ranToday": last_run_ms > 0 && bj_day(last_run_ms) == today,
            }));
        }
        json!({"count": out.len(), "today": today, "accounts": out})
    }

    pub async fn run_all(&self, force: bool) -> Value {
        let list = self.st.list("trae").unwrap_or_default();
        let mut results = Vec::new();
        for a in &list {
            results.push(self.signin_one(a, force).await);
        }
        run_summary(results)
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        self.st.remove("trae", id)
    }

    pub fn rename(&self, id: &str, label: &str) -> Result<(), String> {
        let mut a = self
            .st
            .get("trae", id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "账号不存在".to_string())?;
        a.data.insert("label".into(), json!(label));
        self.st.put("trae", &a.data)
    }
}

fn value_display_or_empty(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(x) => value_display(x),
    }
}

fn run_summary(results: Vec<Value>) -> Value {
    let (mut checked, mut already, mut failed, mut cooling) = (0usize, 0usize, 0usize, 0usize);
    for r in &results {
        match r.get("state").map(str_v).unwrap_or("") {
            "checked" => checked += 1,
            "already" | "skipped" => already += 1,
            "error" | "token_dead" => failed += 1,
            "rate" | "cooldown" | "pending" => cooling += 1,
            _ => {}
        }
    }
    json!({
        "at": bj_string(now_ms()),
        "accounts": results.len(),
        "checked": checked, "already": already, "failed": failed, "cooling": cooling,
        "results": results,
    })
}
