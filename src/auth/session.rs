// src/auth/session.rs
//! Session Management for Authentication
//! 
//! Handles session lifecycle including cookie storage, refresh, and expiration tracking.

use anyhow::{Context, Result};
use rquest::cookie::Jar;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use log::{info, debug};

use super::{AuthMacro, AuthExecutor, AuthResult};

/// Manages authentication session state and automatic refresh
pub struct SessionManager {
    /// The authentication macro to use for (re)authentication
    auth_macro: Option<AuthMacro>,
    
    /// The authentication executor
    executor: AuthExecutor,
    
    /// Current session cookies
    cookies: Arc<RwLock<Option<Arc<Jar>>>>,
    
    /// When the session was last refreshed
    last_refresh: Arc<RwLock<Option<Instant>>>,
    
    /// Session timeout duration (when to proactively refresh)
    session_timeout: Duration,
    
    /// Number of consecutive auth failures
    failure_count: Arc<RwLock<u32>>,
    
    /// Maximum retry attempts
    max_retries: u32,
}

impl SessionManager {
    /// Create a new session manager without an auth macro
    pub fn new() -> Self {
        Self {
            auth_macro: None,
            executor: AuthExecutor::new(),
            cookies: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(None)),
            session_timeout: Duration::from_secs(30 * 60), // 30 minutes
            failure_count: Arc::new(RwLock::new(0)),
            max_retries: 3,
        }
    }
    
    /// Create a session manager with an authentication macro
    pub fn with_macro(auth_macro: AuthMacro) -> Self {
        Self {
            auth_macro: Some(auth_macro),
            executor: AuthExecutor::new(),
            cookies: Arc::new(RwLock::new(None)),
            last_refresh: Arc::new(RwLock::new(None)),
            session_timeout: Duration::from_secs(30 * 60),
            failure_count: Arc::new(RwLock::new(0)),
            max_retries: 3,
        }
    }
    
    /// Load auth macro from file
    pub fn from_file(path: &str) -> Result<Self> {
        let macro_def = AuthMacro::from_file(path)?;
        Ok(Self::with_macro(macro_def))
    }
    
    /// Set a custom executor
    pub fn with_executor(mut self, executor: AuthExecutor) -> Self {
        self.executor = executor;
        self
    }
    
    /// Set session timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }
    
    /// Set maximum retry attempts
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
    
    /// Check if we have an active session
    pub async fn has_session(&self) -> bool {
        self.cookies.read().await.is_some()
    }
    
    /// Check if session needs refresh (expired or about to expire)
    pub async fn needs_refresh(&self) -> bool {
        let last_refresh = self.last_refresh.read().await;
        match *last_refresh {
            Some(instant) => instant.elapsed() > self.session_timeout,
            None => true,
        }
    }
    
    /// Get current cookies (if any)
    pub async fn get_cookies(&self) -> Option<Arc<Jar>> {
        self.cookies.read().await.clone()
    }
    
    /// Get raw cookie string for headers
    pub async fn get_cookie_header(&self) -> Option<String> {
        // Note: This would need access to the raw cookies stored
        // For now, return None and use the Jar directly
        None
    }
    
    /// Perform authentication and store session
    pub async fn authenticate(&self) -> Result<bool> {
        let macro_def = match &self.auth_macro {
            Some(m) => m,
            None => {
                debug!("No auth macro configured, skipping authentication");
                return Ok(false);
            }
        };
        
        info!("Performing authentication using macro: {}", macro_def.name);
        
        // Execute auth in a blocking context (headless_chrome is not async)
        let executor = self.executor.clone();
        let macro_clone = macro_def.clone();
        
        let result: Result<AuthResult> = tokio::task::spawn_blocking(move || {
            executor.execute(&macro_clone)
        }).await
            .context("Auth task panicked")?;
        
        match result {
            Ok(auth_result) if auth_result.success => {
                if let Some(cookies) = auth_result.cookies {
                    *self.cookies.write().await = Some(cookies);
                    *self.last_refresh.write().await = Some(Instant::now());
                    *self.failure_count.write().await = 0;
                    
                    info!("Authentication successful, captured {} cookies", 
                          auth_result.raw_cookies.len());
                    Ok(true)
                } else {
                    info!("Authentication succeeded but no cookies captured");
                    Ok(false)
                }
            }
            Ok(auth_result) => {
                let mut count = self.failure_count.write().await;
                *count += 1;
                
                let error = auth_result.error.unwrap_or_else(|| "Unknown error".to_string());
                log::warn!("Authentication failed (attempt {}): {}", *count, error);
                
                if *count >= self.max_retries {
                    anyhow::bail!("Max auth retries exceeded: {}", error);
                }
                
                Ok(false)
            }
            Err(e) => {
                let mut count = self.failure_count.write().await;
                *count += 1;
                
                log::warn!("Authentication error (attempt {}): {}", *count, e);
                
                if *count >= self.max_retries {
                    return Err(e);
                }
                
                Ok(false)
            }
        }
    }
    
    /// Handle an authentication challenge (401/403 response)
    pub async fn handle_challenge(&self, status_code: u16) -> Result<bool> {
        if status_code != 401 && status_code != 403 {
            return Ok(false);
        }
        
        info!("Handling auth challenge ({}), refreshing session...", status_code);
        
        // Clear current session
        *self.cookies.write().await = None;
        
        // Re-authenticate
        self.authenticate().await
    }
    
    /// Ensure we have a valid session, authenticating if necessary
    pub async fn ensure_session(&self) -> Result<Option<Arc<Jar>>> {
        // Check if we need to authenticate
        if self.auth_macro.is_none() {
            return Ok(None);
        }
        
        if !self.has_session().await || self.needs_refresh().await {
            self.authenticate().await?;
        }
        
        Ok(self.get_cookies().await)
    }
    
    /// Invalidate current session
    pub async fn invalidate(&self) {
        *self.cookies.write().await = None;
        *self.last_refresh.write().await = None;
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AuthExecutor {
    fn clone(&self) -> Self {
        Self {
            headless: self.headless,
            timeout: self.timeout,
            chrome_path: self.chrome_path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_session_manager_no_macro() {
        let manager = SessionManager::new();
        
        assert!(!manager.has_session().await);
        assert!(manager.needs_refresh().await);
        
        // Should succeed but return false (no macro configured)
        let result = manager.authenticate().await.unwrap();
        assert!(!result);
    }
    
    #[tokio::test]
    async fn test_session_timeout_detection() {
        let manager = SessionManager::new()
            .with_timeout(Duration::from_millis(100));
        
        // Initially needs refresh (no session)
        assert!(manager.needs_refresh().await);
        
        // Simulate having a session
        *manager.last_refresh.write().await = Some(Instant::now());
        
        // Should not need refresh immediately
        assert!(!manager.needs_refresh().await);
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should need refresh now
        assert!(manager.needs_refresh().await);
    }
}
