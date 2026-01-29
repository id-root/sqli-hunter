// src/auth/macro_executor.rs
//! Authentication Macro System
//! 
//! Executes YAML-defined authentication workflows using headless Chrome
//! to obtain session cookies for authenticated endpoint scanning.

use anyhow::{anyhow, Context, Result};
use headless_chrome::{Browser, LaunchOptions, Tab};
use rquest::cookie::{CookieStore, Jar};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use log::{info, warn, debug};
use url::Url;

/// Actions that can be performed in an authentication macro
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthAction {
    /// Navigate to a URL
    Navigate,
    /// Click on an element
    Click,
    /// Type text into an element
    Type,
    /// Submit a form
    Submit,
    /// Wait for an element to appear
    WaitForSelector,
    /// Wait for navigation to complete
    WaitForNavigation,
    /// Execute JavaScript
    ExecuteJs,
    /// Take a screenshot (for debugging)
    Screenshot,
    /// Wait a fixed duration
    Sleep,
    /// Clear an input field before typing
    ClearAndType,
}

/// A single step in an authentication macro
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthStep {
    /// The action to perform
    pub action: AuthAction,
    
    /// CSS selector for the target element (if applicable)
    #[serde(default)]
    pub selector: String,
    
    /// Value to use (URL for Navigate, text for Type, JS for ExecuteJs)
    #[serde(default)]
    pub value: Option<String>,
    
    /// Wait duration in milliseconds before next step
    #[serde(default = "default_wait")]
    pub wait_ms: u64,
    
    /// Optional description for logging
    #[serde(default)]
    pub description: Option<String>,
    
    /// Whether this step is optional (won't fail if element not found)
    #[serde(default)]
    pub optional: bool,
}

fn default_wait() -> u64 {
    500
}

/// Complete authentication macro definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthMacro {
    /// Name of this authentication macro
    pub name: String,
    
    /// Target URL to authenticate against
    pub target_url: String,
    
    /// Description of what this macro does
    #[serde(default)]
    pub description: Option<String>,
    
    /// Steps to execute
    pub steps: Vec<AuthStep>,
    
    /// Cookie domains to capture (if empty, uses target_url domain)
    #[serde(default)]
    pub cookie_domains: Vec<String>,
    
    /// Success indicator - selector that should exist after successful auth
    #[serde(default)]
    pub success_indicator: Option<String>,
    
    /// Failure indicators - if any of these exist, auth failed
    #[serde(default)]
    pub failure_indicators: Vec<String>,
}

impl AuthMacro {
    /// Load an authentication macro from a YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read auth macro file: {:?}", path.as_ref()))?;
        
        Self::from_yaml(&content)
    }
    
    /// Parse an authentication macro from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml)
            .with_context(|| "Failed to parse auth macro YAML")
    }
    
    /// Validate the macro configuration
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("Auth macro name cannot be empty"));
        }
        
        if self.steps.is_empty() {
            return Err(anyhow!("Auth macro must have at least one step"));
        }
        
        // Validate target URL
        Url::parse(&self.target_url)
            .with_context(|| format!("Invalid target URL: {}", self.target_url))?;
        
        // Validate steps
        for (i, step) in self.steps.iter().enumerate() {
            match step.action {
                AuthAction::Navigate => {
                    if step.value.is_none() {
                        return Err(anyhow!("Step {}: Navigate action requires a URL value", i + 1));
                    }
                }
                AuthAction::Click | AuthAction::WaitForSelector | AuthAction::Submit => {
                    if step.selector.is_empty() {
                        return Err(anyhow!("Step {}: {:?} action requires a selector", i + 1, step.action));
                    }
                }
                AuthAction::Type | AuthAction::ClearAndType => {
                    if step.selector.is_empty() {
                        return Err(anyhow!("Step {}: Type action requires a selector", i + 1));
                    }
                    if step.value.is_none() {
                        return Err(anyhow!("Step {}: Type action requires a value", i + 1));
                    }
                }
                AuthAction::ExecuteJs => {
                    if step.value.is_none() {
                        return Err(anyhow!("Step {}: ExecuteJs requires JavaScript code in value", i + 1));
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
}

/// Result of executing an authentication macro
#[derive(Debug)]
pub struct AuthResult {
    /// Whether authentication succeeded
    pub success: bool,
    
    /// Captured cookies as a CookieJar
    pub cookies: Option<Arc<Jar>>,
    
    /// Raw cookie strings for debugging
    pub raw_cookies: Vec<String>,
    
    /// Any error message if auth failed
    pub error: Option<String>,
    
    /// Screenshot path if taken
    pub screenshot_path: Option<String>,
}

/// Executor for authentication macros
pub struct AuthExecutor {
    /// Browser launch options
    pub headless: bool,
    
    /// Timeout for browser operations
    pub timeout: Duration,
    
    /// Path to Chrome/Chromium executable (None = auto-detect)
    pub chrome_path: Option<String>,
}

impl Default for AuthExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthExecutor {
    /// Create a new AuthExecutor with default settings
    pub fn new() -> Self {
        Self {
            headless: true,
            timeout: Duration::from_secs(30),
            chrome_path: None,
        }
    }
    
    /// Set whether to run browser in headless mode
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }
    
    /// Set the timeout for browser operations
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Set a custom Chrome path
    pub fn chrome_path(mut self, path: Option<String>) -> Self {
        self.chrome_path = path;
        self
    }
    
    /// Execute an authentication macro and return the session cookies
    pub fn execute(&self, macro_def: &AuthMacro) -> Result<AuthResult> {
        // Validate the macro first
        macro_def.validate()?;
        
        info!("Executing auth macro: {}", macro_def.name);
        
        // Launch browser
        let browser = self.launch_browser()?;
        let tab = browser.new_tab()?;
        
        // Execute steps
        let mut last_error: Option<String> = None;
        
        for (i, step) in macro_def.steps.iter().enumerate() {
            let default_desc = format!("{:?} on {}", step.action, step.selector);
            let step_desc = step.description.as_deref().unwrap_or(&default_desc);
            
            debug!("Executing step {}: {}", i + 1, step_desc);
            
            match self.execute_step(&tab, step) {
                Ok(_) => {
                    // Wait after step
                    if step.wait_ms > 0 {
                        std::thread::sleep(Duration::from_millis(step.wait_ms));
                    }
                }
                Err(e) => {
                    if step.optional {
                        warn!("Optional step {} failed (continuing): {}", i + 1, e);
                    } else {
                        last_error = Some(format!("Step {} failed: {}", i + 1, e));
                        break;
                    }
                }
            }
        }
        
        // Check for failure indicators
        for indicator in &macro_def.failure_indicators {
            if !indicator.is_empty() {
                if let Ok(_) = tab.wait_for_element_with_custom_timeout(indicator, Duration::from_millis(500)) {
                    last_error = Some(format!("Failure indicator found: {}", indicator));
                    break;
                }
            }
        }
        
        // Check for success indicator
        let success = if last_error.is_none() {
            if let Some(ref indicator) = macro_def.success_indicator {
                match tab.wait_for_element_with_custom_timeout(indicator, Duration::from_secs(5)) {
                    Ok(_) => true,
                    Err(_) => {
                        last_error = Some(format!("Success indicator not found: {}", indicator));
                        false
                    }
                }
            } else {
                true // No indicator = assume success
            }
        } else {
            false
        };
        
        // Extract cookies
        let (cookies, raw_cookies) = if success {
            self.extract_cookies(&tab, macro_def)?
        } else {
            (None, vec![])
        };
        
        Ok(AuthResult {
            success,
            cookies,
            raw_cookies,
            error: last_error,
            screenshot_path: None,
        })
    }
    
    /// Launch the browser
    fn launch_browser(&self) -> Result<Browser> {
        let mut options = LaunchOptions::default_builder();
        options.headless(self.headless);
        
        // Extend idle timeout from default 30s to 120s for slow targets like DVWA
        options.idle_browser_timeout(Duration::from_secs(120));
        
        if let Some(ref path) = self.chrome_path {
            options.path(Some(path.into()));
        }
        
        let options = options.build()
            .map_err(|e| anyhow!("Failed to build launch options: {}", e))?;
        
        Browser::new(options)
            .with_context(|| "Failed to launch browser. Is Chrome/Chromium installed?")
    }
    
    /// Execute a single step
    fn execute_step(&self, tab: &Arc<Tab>, step: &AuthStep) -> Result<()> {
        match step.action {
            AuthAction::Navigate => {
                let url = step.value.as_ref()
                    .ok_or_else(|| anyhow!("Navigate requires URL"))?;
                tab.navigate_to(url)?;
                tab.wait_until_navigated()?;
            }
            
            AuthAction::Click => {
                let element = tab.wait_for_element_with_custom_timeout(
                    &step.selector,
                    self.timeout
                )?;
                element.click()?;
            }
            
            AuthAction::Type => {
                let value = step.value.as_ref()
                    .ok_or_else(|| anyhow!("Type requires value"))?;
                let element = tab.wait_for_element_with_custom_timeout(
                    &step.selector,
                    self.timeout
                )?;
                element.type_into(value)?;
            }
            
            AuthAction::ClearAndType => {
                let value = step.value.as_ref()
                    .ok_or_else(|| anyhow!("ClearAndType requires value"))?;
                let element = tab.wait_for_element_with_custom_timeout(
                    &step.selector,
                    self.timeout
                )?;
                // Clear by selecting all and deleting
                element.click()?;
                tab.press_key("Control+a")?;
                tab.press_key("Backspace")?;
                element.type_into(value)?;
            }
            
            AuthAction::Submit => {
                let element = tab.wait_for_element_with_custom_timeout(
                    &step.selector,
                    self.timeout
                )?;
                // Try to get the form and submit
                element.click()?;
            }
            
            AuthAction::WaitForSelector => {
                tab.wait_for_element_with_custom_timeout(
                    &step.selector,
                    self.timeout
                )?;
            }
            
            AuthAction::WaitForNavigation => {
                tab.wait_until_navigated()?;
            }
            
            AuthAction::ExecuteJs => {
                let js = step.value.as_ref()
                    .ok_or_else(|| anyhow!("ExecuteJs requires JavaScript"))?;
                tab.evaluate(js, false)?;
            }
            
            AuthAction::Screenshot => {
                let _data = tab.capture_screenshot(
                    headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                    None,
                    None,
                    true
                )?;
                // TODO: Save screenshot if path provided
            }
            
            AuthAction::Sleep => {
                let ms = step.value.as_ref()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(step.wait_ms);
                std::thread::sleep(Duration::from_millis(ms));
            }
        }
        
        Ok(())
    }
    
    /// Extract cookies from the browser session
    fn extract_cookies(&self, tab: &Arc<Tab>, macro_def: &AuthMacro) -> Result<(Option<Arc<Jar>>, Vec<String>)> {
        // Get all cookies from the browser
        let cookies_result = tab.get_cookies();
        
        match cookies_result {
            Ok(cookies) => {
                let jar = Jar::default();
                let mut raw_cookies = Vec::new();
                
                // Determine which domains to capture
                let target_url = Url::parse(&macro_def.target_url)?;
                let target_domain = target_url.host_str().unwrap_or("");
                
                let domains: Vec<&str> = if macro_def.cookie_domains.is_empty() {
                    vec![target_domain]
                } else {
                    macro_def.cookie_domains.iter().map(|s| s.as_str()).collect()
                };
                
                for cookie in cookies {
                    // Check if cookie domain matches any of our target domains
                    // cookie.domain and cookie.path are String types
                    let cookie_domain: &str = &cookie.domain;
                    
                    let domain_matches = domains.iter().any(|d| {
                        cookie_domain.ends_with(*d) || d.ends_with(cookie_domain)
                    });
                    
                    if domain_matches {
                        // Get cookie path
                        let cookie_path: &str = &cookie.path;
                        
                        // Check if domain is an IP address
                        // If it is, we should NOT include Domain=... in the cookie string
                        let is_ip = cookie_domain.parse::<std::net::IpAddr>().is_ok();
                        
                        // Build cookie string for the jar
                        let cookie_str = if is_ip {
                            // Host-only cookie for IP address
                            format!(
                                "{}={}; Path={}",
                                cookie.name,
                                cookie.value,
                                cookie_path
                            )
                        } else {
                            // Domain cookie
                            format!(
                                "{}={}; Domain={}; Path={}",
                                cookie.name,
                                cookie.value,
                                cookie_domain,
                                cookie_path
                            )
                        };
                        
                        raw_cookies.push(format!("{}={}", cookie.name, cookie.value));
                        
                        // Add to jar using the target URL
                        let cookie_url_str = if is_ip {
                            format!("{}://{}", target_url.scheme(), cookie_domain)
                        } else {
                            // Ensure leading dot doesn't mess up scheme construction
                            let clean_domain = cookie_domain.trim_start_matches('.');
                            format!("{}://{}", target_url.scheme(), clean_domain)
                        };
                        
                        if let Ok(url) = Url::parse(&cookie_url_str) {
                            debug!("Adding cookie to jar: '{}' for URL '{}'", cookie_str, url);
                            jar.add_cookie_str(&cookie_str, &url);
                        } else {
                            warn!("Failed to parse URL from cookie domain: {}", cookie_url_str);
                        }
                    }
                }
                
                info!("Captured {} cookies from auth session", raw_cookies.len());
                
                if raw_cookies.is_empty() {
                    Ok((None, raw_cookies))
                } else {
                    Ok((Some(Arc::new(jar)), raw_cookies))
                }
            }
            Err(e) => {
                warn!("Failed to extract cookies: {}", e);
                Ok((None, vec![]))
            }
        }
    }
    
    /// Handle authentication challenge (401/403) by re-executing auth
    pub fn handle_auth_challenge(
        &self,
        status_code: u16,
        macro_def: &AuthMacro,
    ) -> Option<AuthResult> {
        if status_code == 401 || status_code == 403 {
            info!("Auth challenge detected ({}), re-authenticating...", status_code);
            match self.execute(macro_def) {
                Ok(result) if result.success => Some(result),
                Ok(result) => {
                    warn!("Re-authentication failed: {:?}", result.error);
                    None
                }
                Err(e) => {
                    warn!("Re-authentication error: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_auth_macro() {
        let yaml = r##"
name: test-login
target_url: http://localhost:3000
description: Test login macro
steps:
  - action: navigate
    value: http://localhost:3000/login
    wait_ms: 1000
  - action: type
    selector: "#username"
    value: admin
  - action: type
    selector: "#password"
    value: password123
  - action: click
    selector: "#submit"
success_indicator: ".dashboard"
failure_indicators:
  - ".error-message"
  - "#login-failed"
"##;
        
        let macro_def = AuthMacro::from_yaml(yaml).unwrap();
        
        assert_eq!(macro_def.name, "test-login");
        assert_eq!(macro_def.target_url, "http://localhost:3000");
        assert_eq!(macro_def.steps.len(), 4);
        assert_eq!(macro_def.steps[0].action, AuthAction::Navigate);
        assert!(macro_def.success_indicator.is_some());
        assert_eq!(macro_def.failure_indicators.len(), 2);
    }
    
    #[test]
    fn test_validate_macro() {
        let valid_macro = AuthMacro {
            name: "test".to_string(),
            target_url: "http://localhost".to_string(),
            description: None,
            steps: vec![
                AuthStep {
                    action: AuthAction::Navigate,
                    selector: String::new(),
                    value: Some("http://localhost/login".to_string()),
                    wait_ms: 500,
                    description: None,
                    optional: false,
                }
            ],
            cookie_domains: vec![],
            success_indicator: None,
            failure_indicators: vec![],
        };
        
        assert!(valid_macro.validate().is_ok());
    }
    
    #[test]
    fn test_invalid_macro_no_steps() {
        let invalid = AuthMacro {
            name: "test".to_string(),
            target_url: "http://localhost".to_string(),
            description: None,
            steps: vec![],
            cookie_domains: vec![],
            success_indicator: None,
            failure_indicators: vec![],
        };
        
        assert!(invalid.validate().is_err());
    }
    
    #[test]
    fn test_auth_action_serde() {
        let yaml = "navigate";
        let action: AuthAction = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(action, AuthAction::Navigate);
        
        let yaml = "clear_and_type";
        let action: AuthAction = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(action, AuthAction::ClearAndType);
    }
}
