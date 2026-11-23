//! 公共工具：编码、时间、HTTP、JWT、ECDSA 设备签名等（对应 Go 版 internal/platform/util.go）。

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, FixedOffset, Timelike, Utc};
use der::pem::LineEnding;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::SecretKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::{Client, Method};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub type JsonMap = Map<String, Value>;

pub fn str_v(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

pub fn first_non_empty<'a>(vals: &[&'a str]) -> &'a str {
    for v in vals {
        if !v.is_empty() {
            return v;
        }
    }
    ""
}

pub fn first_non_empty_owned(vals: &[String]) -> String {
    vals.iter().find(|s| !s.is_empty()).cloned().unwrap_or_default()
}

pub fn to_i64(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().map(|x| x as i64))
            .unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
        Value::String(s) => s.trim().parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

/// 带 HTTP 状态码的接口错误
#[derive(Debug, Clone)]
pub struct ApiErr {
    pub status: u16,
    pub msg: String,
}

impl ApiErr {
    pub fn new(status: u16, msg: impl Into<String>) -> Self {
        Self { status, msg: msg.into() }
    }
}

/// 令牌类错误：fatal=true 表示令牌链断了（对应 JS 的 e.fatal → token_dead）
#[derive(Debug, Clone)]
pub struct TokErr {
    pub msg: String,
    pub fatal: bool,
}

impl TokErr {
    pub fn fatal(msg: impl Into<String>) -> Self {
        Self { msg: msg.into(), fatal: true }
    }
    pub fn soft(msg: impl Into<String>) -> Self {
        Self { msg: msg.into(), fatal: false }
    }
}

/// JS 的 `json.code`：只认数值型，缺失/非数值返回 None（避免把「没有 code」当成 0 = 成功）。
pub fn json_code(v: &Value) -> Option<i64> {
    match v.get("code")? {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        _ => None,
    }
}

/// 把可选 code 渲染成 JS 模板字符串里的样子（缺失显示 ?）
pub fn code_disp(c: Option<i64>) -> String {
    c.map(|x| x.to_string()).unwrap_or_else(|| "?".to_string())
}

/// JS 的真值判断
pub fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map_or(false, |f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// JS 的 `Number(x) || 0`
pub fn num_of(v: &Value) -> f64 {
    let f = match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() { 0.0 } else { t.parse::<f64>().unwrap_or(0.0) }
        }
        Value::Bool(b) => if *b { 1.0 } else { 0.0 },
        _ => 0.0,
    };
    if f.is_finite() { f } else { 0.0 }
}

/// 数值转 JSON：整数保持整数（与 JS 的 JSON.stringify 一致）
pub fn num_value(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// 数值转文本：与 JS 模板字符串一致（100 → "100"，100.5 → "100.5"）
pub fn num_text(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 9e15 { format!("{}", f as i64) } else { format!("{}", f) }
}

/// JS encodeURIComponent：保留 A-Za-z0-9 - _ . ! ~ * ' ( )，其余（含空格）按 %XX
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*'
            | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 合并两个对象：extra 覆盖 base 的同名键。
pub fn merged(base: JsonMap, extra: Value) -> Value {
    let mut m = base;
    if let Value::Object(e) = extra {
        for (k, v) in e {
            m.insert(k, v);
        }
    }
    Value::Object(m)
}

// ---------- 编码 ----------

pub fn b64_encode(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn b64url_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn b64url_decode(s: &str) -> Vec<u8> {
    let pad = (4 - s.len() % 4) % 4;
    let mut t = String::with_capacity(s.len() + pad);
    t.push_str(s);
    t.push_str(&"=".repeat(pad));
    URL_SAFE.decode(t.as_bytes()).unwrap_or_default()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_hex(n: usize) -> String {
    hex::encode(random_bytes(n))
}

pub fn random_id(bytes_n: usize) -> String {
    b64url_encode(&random_bytes(bytes_n))
}

/// 15 位设备号，首位非 0
pub fn gen_device_id() -> String {
    let b = random_bytes(15);
    let mut s = String::with_capacity(15);
    s.push((b'1' + b[0] % 9) as char);
    for x in &b[1..15] {
        s.push((b'0' + x % 10) as char);
    }
    s
}

// ---------- 时间 ----------

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn bj_offset() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).expect(" CST offset")
}

fn bj_datetime(ms: i64) -> DateTime<FixedOffset> {
    DateTime::from_timestamp_millis(ms)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).expect("epoch"))
        .with_timezone(&bj_offset())
}

pub fn bj_day(ms: i64) -> String {
    bj_datetime(ms).format("%Y-%m-%d").to_string()
}

pub fn bj_hour(ms: i64) -> u32 {
    bj_datetime(ms).hour()
}

pub fn bj_string(ms: i64) -> String {
    // 与 JS 的 toISOString().replace('Z',' +08:00') 同形：2026-11-23T18:26:00.000 +08:00
    format!("{} +08:00", bj_datetime(ms).format("%Y-%m-%dT%H:%M:%S%.3f"))
}

// ---------- JWT（只取载荷展示，不校验签名） ----------

pub fn jwt_claims(tok: &str) -> Option<JsonMap> {
    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let data = b64url_decode(parts[1]);
    serde_json::from_slice::<Value>(&data)
        .ok()
        .and_then(|v| v.as_object().cloned())
}

pub fn jwt_exp(tok: &str) -> i64 {
    let claims = match jwt_claims(tok) {
        Some(c) => c,
        None => return 0,
    };
    let mut v = to_i64(claims.get("exp").unwrap_or(&Value::Null));
    if v == 0 {
        v = to_i64(claims.get("TokenExpireAt").unwrap_or(&Value::Null));
    }
    if v > 1_000_000_000_000 {
        v /= 1000;
    }
    v
}

// ---------- HTTP ----------

#[derive(Debug, Default)]
pub struct FetchResult {
    pub status: i32,
    /// 响应不是合法 JSON（或网络失败）时为空对象，此时 is_json=false
    pub json: Value,
    pub text: String,
    pub is_json: bool,
}

fn http_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| Client::builder().build().expect("构建 HTTP 客户端失败"))
}

/// 对应 Go 的 doFetch：默认 Content-Type=application/json，GET 丢弃 body。
pub async fn fetch(
    raw_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body: Option<Vec<u8>>,
    timeout: Duration,
) -> FetchResult {
    let verb = Method::from_bytes(method.to_ascii_uppercase().as_bytes()).unwrap_or(Method::GET);
    let mut req = http_client()
        .request(verb, raw_url)
        .timeout(timeout);

    let has_ct = headers.keys().any(|k| k.eq_ignore_ascii_case("content-type"));
    if !has_ct {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !method.eq_ignore_ascii_case("GET") {
        if let Some(b) = body {
            req = req.body(b);
        }
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16() as i32;
            let text = resp.text().await.unwrap_or_default();
            match serde_json::from_str::<Value>(&text) {
                Ok(json) => FetchResult { status, json, text, is_json: true },
                Err(_) => FetchResult {
                    status,
                    json: Value::Object(JsonMap::new()),
                    text,
                    is_json: false,
                },
            }
        }
        Err(e) => FetchResult {
            status: 0,
            json: Value::Object(JsonMap::new()),
            text: e.to_string(),
            is_json: false,
        },
    }
}

pub fn json_body(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

// ---------- ECDSA P-256 设备签名 ----------

/// 生成一套 P-256 设备密钥，返回 PKCS#8 私钥 PEM 与 SPKI 公钥 PEM。
pub fn gen_device_identity() -> Result<(String, String), String> {
    let secret = SecretKey::random(&mut OsRng);
    let priv_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();
    let pub_pem = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok((priv_pem, pub_pem))
}

/// 用 PKCS#8 PEM 私钥对数据做 SHA-256 + ECDSA 签名，输出 base64(DER)，s 归一化到低半区。
pub fn ec_sign(priv_pem: &str, data: &[u8]) -> Result<String, String> {
    if priv_pem.is_empty() {
        return Err("设备私钥缺失或格式错误".to_string());
    }
    // 优先 PKCS#8；失败再按 SEC1（BEGIN EC PRIVATE KEY）解析，与 JS 版 importPrivateKey 一致
    let key = match SigningKey::from_pkcs8_pem(priv_pem) {
        Ok(k) => k,
        Err(_) => {
            let sk = SecretKey::from_sec1_pem(priv_pem)
                .map_err(|_| "设备私钥缺失或格式错误".to_string())?;
            SigningKey::from(sk)
        }
    };
    let digest = Sha256::digest(data);
    let sig: Signature = key
        .sign_prehash(&digest)
        .map_err(|e| e.to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let der = sig.to_der();
    Ok(b64_encode(der.as_ref()))
}

// ---------- PKCE / UUID ----------

pub fn pkce_pair() -> (String, String) {
    let verifier = random_hex(32);
    let challenge = b64url_encode(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn sha256b64url(s: &str) -> String {
    b64url_encode(&Sha256::digest(s.as_bytes()))
}

pub fn new_uuid() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ---------- 通用查找 ----------

const ACCESS_KEYS: &[&str] = &["AccessToken", "access_token", "token", "Jwt", "JWT"];
const REFRESH_KEYS: &[&str] = &["RefreshToken", "refresh_token"];
const NICK_KEYS: &[&str] = &[
    "Nickname", "nickname", "NickName", "nick_name", "UserName", "userName", "user_name",
    "username", "ScreenName", "screen_name", "DisplayName", "displayName", "display_name",
    "Name", "name",
];

pub fn deep_find(obj: &Value, keys: &[&str], depth: usize) -> String {
    if depth > 6 {
        return String::new();
    }
    match obj {
        Value::Object(m) => {
            for k in keys {
                if let Some(s) = m.get(*k).and_then(Value::as_str) {
                    let t = s.trim();
                    if !t.is_empty() {
                        return t.to_string();
                    }
                }
            }
            for v in m.values() {
                let r = deep_find(v, keys, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                let r = deep_find(v, keys, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
        _ => {}
    }
    String::new()
}

pub fn is_generic_name(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "pc" | "windows" | "web" | "ide" | "trae" | "unknown"
    )
}

pub fn pick_nickname(obj: &Value, depth: usize) -> String {
    if depth > 5 {
        return String::new();
    }
    match obj {
        Value::Object(m) => {
            for k in NICK_KEYS {
                if let Some(s) = m.get(*k).and_then(Value::as_str) {
                    let t = s.trim();
                    if !t.is_empty() && t.chars().count() <= 32 && !is_generic_name(t) {
                        return t.to_string();
                    }
                }
            }
            for v in m.values() {
                let r = pick_nickname(v, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
        Value::Array(a) => {
            for v in a {
                let r = pick_nickname(v, depth + 1);
                if !r.is_empty() {
                    return r;
                }
            }
        }
        _ => {}
    }
    String::new()
}

pub fn nickname_from_jwt(tok: &str) -> String {
    if tok.split('.').count() < 3 {
        return String::new();
    }
    match jwt_claims(tok) {
        Some(c) => pick_nickname(&Value::Object(c), 0),
        None => String::new(),
    }
}

pub fn find_access(obj: &Value) -> String {
    deep_find(obj, ACCESS_KEYS, 0)
}

pub fn find_refresh(obj: &Value) -> String {
    deep_find(obj, REFRESH_KEYS, 0)
}

pub fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
