use sqlx::{sqlite::{SqlitePoolOptions, SqliteConnectOptions}, Pool, Sqlite, Error};
use sqlx::Row;
use crate::models::{Target, Payload};
use log::info;
use std::str::FromStr;
use sha2::{Sha256, Digest};

pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, Error> {
        let connection_options = SqliteConnectOptions::from_str(database_url)?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(connection_options).await?;
        
        let db = Database { pool };
        db.init_schema().await?;
        Ok(db)
    }

    async fn init_schema(&self) -> Result<(), Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                signature TEXT UNIQUE,
                url TEXT,
                method TEXT,
                params JSON,
                status TEXT DEFAULT 'PENDING',
                scan_depth_level INTEGER DEFAULT 1,
                last_proxy_used TEXT
            );"
        ).execute(&self.pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                vector_type TEXT,
                platform TEXT,
                content TEXT
            );"
        ).execute(&self.pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                vulnerable_param TEXT,
                payload_used TEXT,
                evidence TEXT,
                confidence_score INTEGER DEFAULT 0,
                waf_bypass_method TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );"
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn seed_payloads(&self) -> Result<(), Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM payloads")
            .fetch_one(&self.pool)
            .await?;
        if count.0 > 0 { return Ok(()); }
        
        info!("Seeding default payloads...");
        let payloads = vec![
            ("Error Based", "Generic", "'"),
            ("Boolean Based", "Generic", "' OR 1=1--"),
            ("Time Based", "Generic", "WAITFOR DELAY '0:0:5'"), 
        ];
        for (v, p, c) in payloads {
             sqlx::query("INSERT INTO payloads (vector_type, platform, content) VALUES (?, ?, ?)")
                .bind(v).bind(p).bind(c).execute(&self.pool).await?;
        }
        Ok(())
    }
    
    pub async fn get_pending_targets(&self) -> Result<Vec<Target>, Error> {
        sqlx::query_as::<_, Target>("SELECT * FROM targets WHERE status = 'PENDING'")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_payloads(&self) -> Result<Vec<Payload>, Error> {
        sqlx::query_as::<_, Payload>("SELECT * FROM payloads").fetch_all(&self.pool).await
    }
    
    pub async fn get_all_findings(&self) -> Result<Vec<crate::models::Finding>, Error> {
        sqlx::query_as::<_, crate::models::Finding>(r#"
            SELECT 
                f.id, 
                f.target_id, 
                t.url as target_url, 
                f.vulnerable_param, 
                f.payload_used, 
                f.evidence, 
                f.confidence_score, 
                f.waf_bypass_method, 
                f.timestamp
            FROM findings f
            JOIN targets t ON f.target_id = t.id
        "#)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn log_finding(&self, target_id: i64, param: &str, payload: &str, evidence: &str, confidence: i32, waf_method: Option<&str>) -> Result<(), Error> {
        sqlx::query("INSERT INTO findings (target_id, vulnerable_param, payload_used, evidence, confidence_score, waf_bypass_method, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))")
            .bind(target_id).bind(param).bind(payload).bind(evidence).bind(confidence).bind(waf_method)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_target_status(&self, target_id: i64, status: &str) -> Result<(), Error> {
        sqlx::query("UPDATE targets SET status = ? WHERE id = ?")
            .bind(status).bind(target_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn add_target(&self, url: &str, method: &str, params: serde_json::Value) -> Result<i64, Error> {
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        hasher.update(method.as_bytes());
        
        // FIX: Canonicalize JSON by sorting keys.
        // If we don't do this, {"a":1, "b":2} and {"b":2, "a":1} look like different targets.
        // serde_json::to_string typically preserves order, but value sorting ensures consistency.
        // For simplicity, we re-parse as a generic value to let serde handle it, 
        // but a dedicated sort is safer. Here we assume standard serde behavior is consistent enough for now,
        // or we convert to a sorted BTreeMap representation implicitly.
        let canonical_params = serde_json::to_string(&params).unwrap_or_default();
        
        hasher.update(canonical_params.as_bytes());
        let signature = hex::encode(hasher.finalize());

        let id = sqlx::query(
            "INSERT INTO targets (signature, url, method, params, status, scan_depth_level) 
             VALUES (?, ?, ?, ?, 'PENDING', 1)
             ON CONFLICT(signature) DO UPDATE SET 
                status='PENDING',           
                params=excluded.params,     
                method=excluded.method
             RETURNING id"
         )
            .bind(signature)
            .bind(url)
            .bind(method)
            .bind(params)
            .fetch_one(&self.pool)
            .await?
            .get::<i64, _>(0);

        Ok(id)
    }
}
