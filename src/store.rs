//! SQLite 存储层（对应 Go 版 internal/store/store.go）。
//! 单表 accounts 存三平台账号，sessions 存登录态；与原版共用同一数据库文件结构。

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::util::{now_ms, to_i64};

#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub data: Map<String, Value>,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS accounts (
                 platform TEXT NOT NULL,
                 id       TEXT NOT NULL,
                 payload  TEXT NOT NULL,
                 created  INTEGER NOT NULL,
                 PRIMARY KEY (platform, id)
             );
             CREATE TABLE IF NOT EXISTS sessions (
                 platform TEXT NOT NULL,
                 key      TEXT NOT NULL,
                 payload  TEXT NOT NULL,
                 expires  INTEGER NOT NULL,
                 PRIMARY KEY (platform, key)
             );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// 某平台全部账号，按创建时间升序。
    pub fn list(&self, platform: &str) -> Result<Vec<Account>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, payload FROM accounts WHERE platform=?1 ORDER BY created ASC, rowid ASC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![platform], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let (id, payload) = row.map_err(|e| e.to_string())?;
            let data = match serde_json::from_str::<Value>(&payload) {
                Ok(Value::Object(m)) => m,
                _ => continue, // 损坏记录跳过，与 Go 一致
            };
            out.push(Account {
                id,
                data,
            });
        }
        Ok(out)
    }

    pub fn get(&self, platform: &str, id: &str) -> Result<Option<Account>, String> {
        let conn = self.conn.lock().unwrap();
        let payload: Option<String> = conn
            .query_row(
                "SELECT payload FROM accounts WHERE platform=?1 AND id=?2",
                params![platform, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let payload = match payload {
            Some(p) => p,
            None => return Ok(None),
        };
        let data = match serde_json::from_str::<Value>(&payload) {
            Ok(Value::Object(m)) => m,
            other => {
                return Err(format!("账号数据解析失败: {:?}", other.err()));
            }
        };
        Ok(Some(Account {
            id: id.to_string(),
            data,
        }))
    }

    /// 新增或更新账号（data 里带 id）。
    pub fn put(&self, platform: &str, data: &Map<String, Value>) -> Result<(), String> {
        let id = data
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let payload = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let created = data.get("createdAt").map(to_i64).unwrap_or(0);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO accounts(platform,id,payload,created) VALUES(?1,?2,?3,?4)
             ON CONFLICT(platform,id) DO UPDATE SET payload=excluded.payload",
            params![platform, id, payload, created],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn remove(&self, platform: &str, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM accounts WHERE platform=?1 AND id=?2",
            params![platform, id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- 登录会话 ----------

    pub fn set_session(
        &self,
        platform: &str,
        key: &str,
        data: &Map<String, Value>,
        ttl_sec: i64,
    ) -> Result<(), String> {
        let payload = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let expires = now_ms() + ttl_sec * 1000;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions(platform,key,payload,expires) VALUES(?1,?2,?3,?4)
             ON CONFLICT(platform,key) DO UPDATE SET payload=excluded.payload, expires=excluded.expires",
            params![platform, key, payload, expires],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_session(&self, platform: &str, key: &str) -> Option<Map<String, Value>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT payload, expires FROM sessions WHERE platform=?1 AND key=?2",
                params![platform, key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        let (payload, expires) = row?;
        if expires < now_ms() {
            return None;
        }
        match serde_json::from_str::<Value>(&payload) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        }
    }

    pub fn del_session(&self, platform: &str, key: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM sessions WHERE platform=?1 AND key=?2",
            params![platform, key],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
