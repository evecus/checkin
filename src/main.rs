//! 签到控制台（Rust 版）：CLI、路由、鉴权、定时签到。
//! 功能与 Go 版 main.go 等价，网页直接内嵌复用。

mod platform;
mod store;
mod util;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use chrono::FixedOffset;
use platform::qoder::Qoder;
use platform::trae::Trae;
use platform::workbuddy::WorkBuddy;
use serde_json::{json, Map, Value};
use store::Store;
use subtle::ConstantTimeEq;
use util::now_ms;

const INDEX_HTML: &str = include_str!("../web/index.html");

struct AppState {
    trae: Arc<Trae>,
    wb: Arc<WorkBuddy>,
    qoder: Arc<Qoder>,
    auth: String,
    cron_secret: String,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let (port, auth, cron_expr, db_path, cron_secret) = parse_args();

    let st = Arc::new(Store::open(&db_path).unwrap_or_else(|e| {
        log::error!("打开数据库失败: {}", e);
        std::process::exit(1);
    }));
    let state = Arc::new(AppState {
        trae: Arc::new(Trae::new(st.clone())),
        wb: Arc::new(WorkBuddy::new(st.clone())),
        qoder: Arc::new(Qoder::new(st.clone())),
        auth,
        cron_secret,
    });

    // 定时签到：5 段北京时间表达式补 0 秒后注册（星期字段按标准 cron 语义转换）。
    if !cron_expr.is_empty() {
        let fields: Vec<&str> = cron_expr.split_whitespace().collect();
        let expr6 = if fields.len() == 5 {
            format!(
                "0 {} {} {} {} {}",
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                convert_dow(fields[4])
            )
        } else {
            cron_expr.clone()
        };
        let schedule = cron::Schedule::from_str(&expr6).unwrap_or_else(|e| {
            log::error!("cron 表达式无效: {}", e);
            std::process::exit(1);
        });
        let st2 = state.clone();
        tokio::spawn(async move {
            let bj = FixedOffset::east_opt(8 * 3600).expect("CST");
            loop {
                let now = chrono::Utc::now().with_timezone(&bj);
                if let Some(next) = schedule.upcoming(bj).next() {
                    let wait = (next - now).to_std().unwrap_or(Duration::from_secs(1));
                    tokio::time::sleep(wait).await;
                    log::info!("[cron] 开始定时签到 {}", util::bj_string(now_ms()));
                    let res = run_all(&st2, false).await;
                    log::info!("[cron] 完成: {}", res);
                    // 避免同一秒内重复触发
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                } else {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });
        log::info!("定时签到已启用（北京时间）: {}", cron_expr);
    }

    let app = build_router(state.clone());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("构建 tokio 运行时失败");
    runtime.block_on(async move {
        log::info!(
            "签到控制台已启动: http://0.0.0.0:{}  （数据文件 {}）",
            port,
            db_path
        );
        if state.auth.is_empty() {
            log::warn!("未设置 -auth，控制台无需密码即可访问");
        }
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .unwrap_or_else(|e| {
                log::error!("服务退出: {}", e);
                std::process::exit(1);
            });
        if let Err(e) = axum::serve(listener, app).await {
            log::error!("服务退出: {}", e);
        }
    });
}

fn parse_args() -> (u16, String, String, String, String) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut port = 8080u16;
    let mut auth = String::new();
    let mut cron_expr = String::new();
    let mut db_path = "checkin.db".to_string();
    let mut cron_secret = String::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let flag = key.trim_start_matches('-');
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                args.get(i).cloned().unwrap_or_default()
            }
        };
        match flag {
            "p" | "port" => port = value.parse().unwrap_or(port),
            "auth" => auth = value,
            "cron" => cron_expr = value,
            "db" => db_path = value,
            "cron-secret" => cron_secret = value,
            "h" | "help" => {
                println!(
                    "用法: checkin-rs [-p 端口] [-auth 密码] [-cron '分 时 日 月 周'] [-cron-secret 口令] [-db 路径]"
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (port, auth, cron_expr, db_path, cron_secret)
}

/// 标准 cron 星期（0/7=周日、1=周一…6=周六）→ cron crate（1=周日…7=周六）。
/// 不转换的话 `1-5` 会被当成「周日到周四」。
fn convert_dow(field: &str) -> String {
    let conv = |t: &str| -> String {
        match t.parse::<u32>() {
            Ok(n) => (n % 7 + 1).to_string(),
            Err(_) => t.to_string(),
        }
    };
    field
        .split(',')
        .map(|part| {
            let (range, step) = match part.split_once('/') {
                Some((r, st)) => (r, Some(st)),
                None => (part, None),
            };
            let body = match range.split_once('-') {
                Some((a, b)) => match (a.parse::<u32>(), b.parse::<u32>(), step) {
                    // 末端写 7 表示周日：拆成「起点-周六」+「周日」
                    (Ok(an), Ok(7), None) if an != 7 => {
                        if an == 0 { "1-7".to_string() } else { format!("{}-7,1", an + 1) }
                    }
                    _ => format!("{}-{}", conv(a), conv(b)),
                },
                None => conv(range),
            };
            match step {
                Some(st) => format!("{}/{}", body, st),
                None => body,
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

async fn run_all(state: &AppState, force: bool) -> Value {
    json!({
        "at": util::bj_string(now_ms()),
        "trae": state.trae.run_all(force).await,
        "wb": state.wb.run_all(force).await,
        "qoder": state.qoder.run_all(force).await,
    })
}

fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/ping", get(ping))
        .route("/api/run-all", post(run_all_handler))
        .route("/trae/api/list", get(trae_list))
        .route("/trae/api/run", post(trae_run))
        .route("/trae/api/accounts/remove", post(trae_remove))
        .route("/trae/api/remove", post(trae_remove))
        .route("/trae/api/rename", post(trae_rename))
        .route("/trae/api/login/start", post(trae_login_start))
        .route("/trae/api/login/claim", post(trae_login_claim))
        .route("/trae/api/login/poll", get(trae_login_poll))
        .route("/wb/api/list", get(wb_list))
        .route("/wb/api/run", post(wb_run))
        .route("/wb/api/remove", post(wb_remove))
        .route("/wb/api/rename", post(wb_rename))
        .route("/wb/api/login/start", post(wb_login_start))
        .route("/wb/api/login/poll", get(wb_login_poll))
        .route("/qoder/api/list", get(qoder_list))
        .route("/qoder/api/run", post(qoder_run))
        .route("/qoder/api/remove", post(qoder_remove))
        .route("/qoder/api/rename", post(qoder_rename))
        .route("/qoder/api/login/start", post(qoder_login_start))
        .route("/qoder/api/login/poll", get(qoder_login_poll))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        // 定时入口：口令走 X-Cron-Secret / ?key=，不要求登录密码
        .route("/cron", any(cron_handler))
        .merge(protected)
        .fallback(not_found)
        .with_state(state)
}

async fn not_found() -> Response {
    json_resp(StatusCode::NOT_FOUND, json!({"error": "not found"}))
}

fn json_resp(status: StatusCode, v: Value) -> Response {
    let mut r = (status, Json(v)).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn index() -> Response {
    let mut r = INDEX_HTML.into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn query_param(req: &Request, key: &str) -> String {
    req.uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default()
}

fn check_auth(req: &Request, auth: &str) -> bool {
    let headers = req.headers();
    let mut given = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if given.is_empty() {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // 对应 JS 的 replace(/^Bearer\s+/i, '')
        let b = bearer.trim_start();
        given = if b.len() > 6 && b[..6].eq_ignore_ascii_case("bearer") && b[6..].starts_with(char::is_whitespace) {
            b[6..].trim_start().to_string()
        } else {
            bearer.to_string()
        };
    }
    if given.is_empty() {
        given = query_param(req, "token");
    }
    bool::from(given.as_bytes().ct_eq(auth.as_bytes()))
}

async fn auth_middleware(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if !st.auth.is_empty() && !check_auth(&req, &st.auth) {
        return json_resp(
            StatusCode::UNAUTHORIZED,
            json!({"error": "访问口令不正确"}),
        );
    }
    next.run(req).await
}

async fn read_body(req: Request) -> Map<String, Value> {
    let bytes = match to_bytes(req.into_body(), 1 << 20).await {
        Ok(b) => b,
        Err(_) => return Map::new(),
    };
    if bytes.is_empty() {
        return Map::new();
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn body_str(body: &Map<String, Value>, key: &str) -> String {
    // 对应 JS 的 String(body[key] ?? '')
    match body.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

// ---------- 通用 ----------

async fn ping() -> Response {
    json_resp(StatusCode::OK, json!({"ok": true}))
}

async fn run_all_handler(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let force = query_param(&req, "force") == "1";
    json_resp(StatusCode::OK, run_all(&st, force).await)
}

async fn cron_handler(State(st): State<Arc<AppState>>, req: Request) -> Response {
    // 口令：CRON_SECRET 缺省回落到登录密码；两者都没设就不设防
    let secret = if st.cron_secret.is_empty() { &st.auth } else { &st.cron_secret };
    if !secret.is_empty() {
        let given = req
            .headers()
            .get("x-cron-secret")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| query_param(&req, "key"));
        let ok = bool::from(given.as_bytes().ct_eq(secret.as_bytes()))
            || (!st.auth.is_empty() && check_auth(&req, &st.auth));
        if !ok {
            return json_resp(StatusCode::UNAUTHORIZED, json!({"error": "口令不对"}));
        }
    }
    json_resp(StatusCode::OK, run_all(&st, false).await)
}

fn remove_handler<F>(body: Map<String, Value>, f: F) -> Response
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let id = body_str(&body, "id").trim().to_string();
    if id.is_empty() {
        return json_resp(StatusCode::BAD_REQUEST, json!({"error": "缺少 id"}));
    }
    if let Err(e) = f(&id) {
        return json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e}));
    }
    json_resp(StatusCode::OK, json!({"ok": true, "removed": id}))
}

fn rename_handler<F>(body: Map<String, Value>, f: F) -> Response
where
    F: FnOnce(&str, &str) -> Result<(), String>,
{
    let id = body_str(&body, "id").trim().to_string();
    // 备注最长 40 字
    let label: String = body_str(&body, "label").trim().chars().take(40).collect();
    let label = label.trim().to_string();
    if id.is_empty() {
        return json_resp(StatusCode::BAD_REQUEST, json!({"error": "缺少 id"}));
    }
    if label.is_empty() {
        return json_resp(StatusCode::BAD_REQUEST, json!({"error": "备注不能为空"}));
    }
    if let Err(e) = f(&id, &label) {
        let status = if e == "账号不存在" { StatusCode::NOT_FOUND } else { StatusCode::INTERNAL_SERVER_ERROR };
        return json_resp(status, json!({"error": e}));
    }
    json_resp(StatusCode::OK, json!({"ok": true, "id": id, "label": label}))
}

// ---------- Trae ----------

async fn trae_list(State(st): State<Arc<AppState>>) -> Response {
    json_resp(StatusCode::OK, st.trae.list())
}

async fn trae_run(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let force = query_param(&req, "force") == "1";
    json_resp(StatusCode::OK, st.trae.run_all(force).await)
}

async fn trae_remove(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let trae = st.trae.clone();
    remove_handler(body, |id| trae.remove(id))
}

async fn trae_rename(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let trae = st.trae.clone();
    rename_handler(body, |id, label| trae.rename(id, label))
}

async fn trae_login_start(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    match st.trae.login_start(&body) {
        Ok(v) => json_resp(StatusCode::OK, v),
        Err(e) => json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

async fn trae_login_claim(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let raw = {
        let a = body_str(&body, "url");
        if a.trim().is_empty() {
            body_str(&body, "text")
        } else {
            a
        }
    };
    api_result(st.trae.login_claim(&raw).await)
}

async fn trae_login_poll(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let trace = query_param(&req, "trace");
    api_result(st.trae.login_poll(&trace))
}

fn api_result(r: Result<Value, util::ApiErr>) -> Response {
    match r {
        Ok(v) => json_resp(StatusCode::OK, v),
        Err(e) => json_resp(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            json!({"error": e.msg}),
        ),
    }
}

// ---------- WorkBuddy ----------

async fn wb_list(State(st): State<Arc<AppState>>) -> Response {
    json_resp(StatusCode::OK, st.wb.list())
}

async fn wb_run(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let force = query_param(&req, "force") == "1";
    json_resp(StatusCode::OK, st.wb.run_all(force).await)
}

async fn wb_remove(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let wb = st.wb.clone();
    remove_handler(body, |id| wb.remove(id))
}

async fn wb_rename(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let wb = st.wb.clone();
    rename_handler(body, |id, label| wb.rename(id, label))
}

async fn wb_login_start(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    match st.wb.login_start(&body).await {
        Ok(v) => json_resp(StatusCode::OK, v),
        Err(e) => json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

async fn wb_login_poll(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let state_key = query_param(&req, "state");
    api_result(st.wb.login_poll(&state_key).await)
}

// ---------- Qoder ----------

async fn qoder_list(State(st): State<Arc<AppState>>) -> Response {
    json_resp(StatusCode::OK, st.qoder.list())
}

async fn qoder_run(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let force = query_param(&req, "force") == "1";
    json_resp(StatusCode::OK, st.qoder.run_all(force).await)
}

async fn qoder_remove(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let qoder = st.qoder.clone();
    remove_handler(body, |id| qoder.remove(id))
}

async fn qoder_rename(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    let qoder = st.qoder.clone();
    rename_handler(body, |id, label| qoder.rename(id, label))
}

async fn qoder_login_start(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let body = read_body(req).await;
    match st.qoder.login_start(&body) {
        Ok(v) => json_resp(StatusCode::OK, v),
        Err(e) => json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    }
}

async fn qoder_login_poll(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let nonce = query_param(&req, "nonce");
    api_result(st.qoder.login_poll(&nonce).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    /// 取接下来 14 天内触发的星期集合（0=周日…6=周六，标准 cron 语义）
    fn weekdays(expr5: &str) -> Vec<u32> {
        let f: Vec<&str> = expr5.split_whitespace().collect();
        let e6 = format!("0 {} {} {} {} {}", f[0], f[1], f[2], f[3], convert_dow(f[4]));
        let sch = cron::Schedule::from_str(&e6).expect("valid");
        let bj = FixedOffset::east_opt(8 * 3600).unwrap();
        let mut set: Vec<u32> = sch
            .upcoming(bj)
            .take(14)
            .map(|t| t.weekday().num_days_from_sunday())
            .collect();
        set.sort();
        set.dedup();
        set
    }

    #[test]
    fn dow_follows_standard_cron() {
        assert_eq!(weekdays("0 8 * * 1-5"), vec![1, 2, 3, 4, 5]);
        assert_eq!(weekdays("0 8 * * 0"), vec![0]);
        assert_eq!(weekdays("0 8 * * 7"), vec![0]);
        assert_eq!(weekdays("0 8 * * 5-7"), vec![0, 5, 6]);
        assert_eq!(weekdays("0 8 * * 1,3"), vec![1, 3]);
        assert_eq!(weekdays("0 8 * * *"), vec![0, 1, 2, 3, 4, 5, 6]);
    }
}
