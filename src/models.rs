use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::NaiveDateTime;

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Target {
    pub id: i64,
    pub signature: Option<String>, 
    pub url: String,
    pub method: String,
    pub params: serde_json::Value,
    pub status: String,
    pub scan_depth_level: i32,
    pub last_proxy_used: Option<String>,
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Payload {
    pub id: i64,
    pub vector_type: String,
    pub platform: String,
    pub content: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub id: i64,
    pub target_id: i64,
    pub target_url: String, // <--- ADDED THIS FIELD
    pub vulnerable_param: String,
    pub payload_used: String,
    pub evidence: String,
    pub confidence_score: i32,
    pub waf_bypass_method: Option<String>,
    pub timestamp: NaiveDateTime,
}
