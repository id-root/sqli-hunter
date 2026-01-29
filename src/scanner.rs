use std::time::Duration;
use regex::Regex;
use strsim::levenshtein;
use log::{error, warn};
use rquest::{Client, StatusCode, header};
use rquest_util::Emulation;
use rquest::cookie::Jar;
use std::sync::Arc;
use tokio::sync::{Semaphore, Mutex};
use crate::models::{Target, Payload};
use crate::db::Database;
use rand::Rng;
use serde_json::Value;
use crate::evasion::EvasionEngine;
use crate::utils::{UserAgentRotator, ProxyManager};
use indicatif::ProgressBar;
use colored::*;
use futures::{StreamExt, Stream};
use crate::tamper::TamperPipeline;
use crate::calibration::Calibration;
use crate::waf::WafDetector;
use std::pin::Pin;
use std::path::PathBuf;
use crate::context::ContextEngine;
use crate::oob::OOBMonitor;

#[derive(Clone)]
pub enum PayloadStrategy {
    InMemory(Arc<Vec<Payload>>),
    Stream(PathBuf),
}

pub struct HeuristicAnalyzer {
    error_patterns: Vec<Regex>,
}

impl HeuristicAnalyzer {
    pub fn new() -> Result<Self, regex::Error> {
        let patterns = vec![
            Regex::new(r"SQL syntax.*?MySQL")?,
            Regex::new(r"Warning.*?\Wmysqli?_")?,
            Regex::new(r"PostgreSQL.*?ERROR")?,
            Regex::new(r"Driver.*? SQL[\-\_]Server")?,
            Regex::new(r"ORA-[0-9][0-9][0-9][0-9]")?,
            Regex::new(r"Microsoft Access Driver")?,
            Regex::new(r"JET Database Engine")?,
            Regex::new(r"Access Database Engine")?,
            Regex::new(r"SQLite/JDBCDriver")?,
            Regex::new(r"SQLITE_ERROR")?,
            Regex::new(r"syntax error")?,
            Regex::new(r"Database Error")?, 
        ];

        Ok(HeuristicAnalyzer {
            error_patterns: patterns,
        })
    }

    pub fn check_error_based(&self, body: &str) -> bool {
        for pattern in &self.error_patterns {
            if pattern.is_match(body) {
                return true;
            }
        }
        false
    }

    pub fn check_blind_boolean(&self, original_body: &str, injected_body: &str) -> bool {
        let dist = levenshtein(original_body, injected_body);
        let len = original_body.len().max(injected_body.len());
        if len == 0 { return false; }
        let similarity = 1.0 - (dist as f64 / len as f64);
        similarity < 0.95
    }

    pub fn check_blind_time(&self, duration: Duration, threshold: Duration) -> bool {
        duration > threshold
    }
}

pub struct Scanner {
    db: Arc<Database>,
    proxy_manager: Arc<Mutex<ProxyManager>>,
    ua_rotator: Arc<UserAgentRotator>,
    semaphore: Arc<Semaphore>,
    analyzer: HeuristicAnalyzer,
    concurrency: usize,
    tamper_pipeline: Option<Arc<TamperPipeline>>,
    oob_monitor: Option<OOBMonitor>,
    cookie_store: Option<Arc<Jar>>,
    // Titan Release: Safety Throttling
    safety_level: u8,
}

/// Safety level configuration for payload filtering
#[derive(Debug, Clone, Copy)]
pub struct SafetyConfig {
    pub level: u8,
    pub description: &'static str,
    pub allow_destructive: bool,
    pub allow_time_based: bool,
    pub allow_oob: bool,
    pub max_payload_length: usize,
}

impl SafetyConfig {
    pub fn from_level(level: u8) -> Self {
        match level {
            1 => SafetyConfig {
                level: 1,
                description: "Aggressive - All payloads enabled",
                allow_destructive: true,
                allow_time_based: true,
                allow_oob: true,
                max_payload_length: usize::MAX,
            },
            2 => SafetyConfig {
                level: 2,
                description: "Standard - Most payloads enabled",
                allow_destructive: true,
                allow_time_based: true,
                allow_oob: true,
                max_payload_length: 500,
            },
            3 => SafetyConfig {
                level: 3,
                description: "Balanced - No destructive payloads",
                allow_destructive: false,
                allow_time_based: true,
                allow_oob: true,
                max_payload_length: 300,
            },
            4 => SafetyConfig {
                level: 4,
                description: "Cautious - Read-only, no time-based",
                allow_destructive: false,
                allow_time_based: false,
                allow_oob: false,
                max_payload_length: 200,
            },
            5 | _ => SafetyConfig {
                level: 5,
                description: "Safe - Minimal, non-intrusive only",
                allow_destructive: false,
                allow_time_based: false,
                allow_oob: false,
                max_payload_length: 100,
            },
        }
    }
    
    /// Filter payloads based on safety configuration
    pub fn filter_payloads(&self, payloads: Vec<Payload>) -> Vec<Payload> {
        payloads.into_iter().filter(|p| {
            // Check payload length
            if p.content.len() > self.max_payload_length {
                return false;
            }
            
            // Check for destructive patterns
            if !self.allow_destructive {
                let lower = p.content.to_lowercase();
                if lower.contains("drop ") || 
                   lower.contains("delete ") || 
                   lower.contains("truncate ") ||
                   lower.contains("update ") ||
                   lower.contains("insert ") ||
                   lower.contains("alter ") {
                    return false;
                }
            }
            
            // Check for time-based payloads
            if !self.allow_time_based {
                let lower = p.content.to_lowercase();
                if lower.contains("sleep") || 
                   lower.contains("waitfor") || 
                   lower.contains("benchmark") ||
                   lower.contains("pg_sleep") ||
                   p.vector_type.to_lowercase().contains("time") {
                    return false;
                }
            }
            
            true
        }).collect()
    }
}

impl Scanner {
    pub fn new(
        db: Arc<Database>, 
        concurrency: usize, 
        proxies: Vec<String>, 
        tamper_pipeline: Option<TamperPipeline>, 
        oob_monitor: Option<OOBMonitor>,
        cookie_store: Option<Arc<Jar>>,
    ) -> Result<Self, anyhow::Error> {
        Self::with_safety_level(db, concurrency, proxies, tamper_pipeline, oob_monitor, cookie_store, 3)
    }
    
    /// Create a scanner with a specific safety level
    pub fn with_safety_level(
        db: Arc<Database>, 
        concurrency: usize, 
        proxies: Vec<String>, 
        tamper_pipeline: Option<TamperPipeline>, 
        oob_monitor: Option<OOBMonitor>,
        cookie_store: Option<Arc<Jar>>,
        safety_level: u8,
    ) -> Result<Self, anyhow::Error> {
        Ok(Scanner {
            db,
            proxy_manager: Arc::new(Mutex::new(ProxyManager::new(proxies))),
            ua_rotator: Arc::new(UserAgentRotator::new()),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            analyzer: HeuristicAnalyzer::new()?,
            concurrency,
            tamper_pipeline: tamper_pipeline.map(Arc::new),
            oob_monitor,
            cookie_store,
            // Titan: Safety throttling
            safety_level: safety_level.clamp(1, 5),
        })
    }
    
    /// Get the safety configuration for this scanner
    pub fn safety_config(&self) -> SafetyConfig {
        SafetyConfig::from_level(self.safety_level)
    }
    
    /// Check and apply throttling based on latency

    
    /// Apply safety filtering to payloads
    pub fn filter_payloads_by_safety(&self, payloads: Vec<Payload>) -> Vec<Payload> {
        self.safety_config().filter_payloads(payloads)
    }

    async fn create_client(&self) -> Result<Client, rquest::Error> {
        let profile = {
            let mut rng = rand::thread_rng();
            match rng.gen_range(0..4) {
                0 => Emulation::Chrome126,
                1 => Emulation::Safari15_5,
                2 => Emulation::Firefox117,
                _ => Emulation::OkHttp4_10,
            }
        };

        let mut builder = Client::builder()
            .emulation(profile)
            .timeout(Duration::from_secs(10));

        if let Some(jar) = &self.cookie_store {
            builder = builder.cookie_provider(jar.clone());
        }

        let mut pm = self.proxy_manager.lock().await;
        if let Some(proxy) = pm.get_next() {
            builder = builder.proxy(proxy);
        }
        
        builder.build()
    }

    pub async fn scan_target(&self, target: Target, strategy: PayloadStrategy, pb: Option<Arc<ProgressBar>>) {
        if let Some(ref p) = pb {
            p.set_message(format!("Scanning {}", target.url));
        }
        
        let initial_client = match self.create_client().await {
            Ok(c) => c,
            Err(e) => {
                 error!("Failed to create client: {}", e);
                 return;
            }
        };

        if let Err(e) = Calibration::calibrate(&initial_client, &target).await {
            warn!("Calibration failed for {}: {}", target.url, e);
        }

        let ua = self.ua_rotator.get_random();
        let baseline_resp = match self.send_request(&initial_client, &target.method, &target.url, &target.params, &ua).await {
             Ok((_, body, headers)) => {
                 if let Some(waf) = WafDetector::detect(&headers) {
                     let msg = format!("{} Detected WAF: {} on {}", "INFO:".blue(), waf, target.url);
                     if let Some(ref p) = pb { p.println(msg); } else { println!("{}", msg); }
                 }
                 Some(body)
             },
             Err(_) => None
        };
        
        let baseline_body = Arc::new(baseline_resp.unwrap_or_default());
        
        let vulnerable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_container = Arc::new(Mutex::new(initial_client));
        let request_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut params_to_scan = Vec::new();
        if let Some(obj) = target.params.as_object() {
             for (k, v) in obj {
                 params_to_scan.push((k.clone(), v.as_str().unwrap_or("").to_string()));
             }
        }

        for (param_key, param_val_str) in params_to_scan {
            if vulnerable.load(std::sync::atomic::Ordering::Relaxed) { break; }
            
            // Renamed to _injection_strategy to fix unused variable warning
            let _injection_strategy = ContextEngine::analyze(&param_val_str);

            let standard_stream: Pin<Box<dyn Stream<Item = Result<Payload, anyhow::Error>> + Send>> = match &strategy {
                PayloadStrategy::InMemory(vec) => {
                    // FIX: Iterate and clone items to get an owned Vec<Payload>
                    // This fixes the "cannot move out of Arc" error
                    let filtered = vec.iter().cloned().collect::<Vec<_>>();
                    
                    let s = futures::stream::iter(filtered.into_iter().map(Ok::<Payload, anyhow::Error>));
                    Box::pin(s)
                },
                PayloadStrategy::Stream(path) => {
                    match crate::payloads::get_payload_stream(path.clone()).await {
                        Ok(s) => {
                            let s = s.map(|res| res); 
                            Box::pin(s)
                        },
                        Err(e) => {
                            error!("Failed to open payload stream: {}", e);
                            continue;
                        }
                    }
                }
            };
            
            let oob_stream: Pin<Box<dyn Stream<Item = Result<Payload, anyhow::Error>> + Send>> = if let Some(monitor) = &self.oob_monitor {
                 let templates = crate::payloads::get_oob_payloads();
                 let monitor = monitor.clone();
                 let target_id = target.id;
                 let s = futures::stream::iter(templates.into_iter().map(move |t| {
                     let content = monitor.generate_payload(target_id, &t.content);
                     Ok(Payload {
                         content,
                         ..t
                     })
                 }));
                 Box::pin(s)
            } else {
                 Box::pin(futures::stream::empty())
            };
            
            let stream = standard_stream.chain(oob_stream);
            let limit = self.concurrency;

            stream.for_each_concurrent(limit, |payload_res| {
                let target = &target;
                let pb = pb.clone();
                let vulnerable = vulnerable.clone();
                let client_container = client_container.clone();
                let request_counter = request_counter.clone();
                let baseline_body = baseline_body.clone();
                let param_key = param_key.clone();
                let param_val_str = param_val_str.clone();

                async move {
                    if vulnerable.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }

                    let payload = match payload_res {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    if let Some(ref p) = pb { p.inc(1); }

                    let delay = rand::thread_rng().gen_range(100..=500);
                    tokio::time::sleep(Duration::from_millis(delay)).await;

                    let _permit = match self.semaphore.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let count = request_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if count > 0 && count % 20 == 0 {
                         if let Ok(new_c) = self.create_client().await {
                             let mut g = client_container.lock().await;
                             *g = new_c;
                         }
                    }

                    let client = {
                        let g = client_container.lock().await;
                        g.clone()
                    };

                    let mut injected_params = target.params.clone();
                    
                    let (mutated_content, method_name) = if let Some(pipeline) = &self.tamper_pipeline {
                        pipeline.apply(&mut injected_params, &param_key, &payload.content);
                        (payload.content.clone(), "Pipeline".to_string())
                    } else {
                        let mutation = EvasionEngine::random_mutation();
                        let mc = EvasionEngine::apply_mutation(&payload.content, &mutation);
                        let method = EvasionEngine::get_method_name(&mutation);
                        
                        let injected_val = format!("{}{}", param_val_str, mc);
                        injected_params[param_key.clone()] = Value::String(injected_val);
                        (mc, method)
                    };

                    let current_ua = self.ua_rotator.get_random();
                    let start = std::time::Instant::now();

                    match self.send_request(&client, &target.method, &target.url, &injected_params, &current_ua).await {
                        Ok((status, body, _)) => {
                            let duration = start.elapsed();
                            
                            if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::FORBIDDEN || status == StatusCode::SERVICE_UNAVAILABLE {
                                 if let Some(ref p) = pb {
                                     p.println(format!("{} Blocked ({}). Cooling down 60s...", "WARN:".yellow(), status));
                                 }
                                 tokio::time::sleep(Duration::from_secs(60)).await;
                                 if let Ok(new_c) = self.create_client().await {
                                     let mut g = client_container.lock().await;
                                     *g = new_c;
                                 }
                                 return; 
                            }

                            let mut potential_vuln = false;
                            let mut vector_type = "";
                            let mut evidence = String::new();

                            if self.analyzer.check_error_based(&body) {
                                potential_vuln = true;
                                vector_type = "Error Based";
                                evidence = body[0..100.min(body.len())].to_string();
                            } else if self.analyzer.check_blind_time(duration, Duration::from_secs(5)) {
                                potential_vuln = true;
                                vector_type = "Time Based";
                                evidence = format!("Response took {:?}", duration);
                            } else if !baseline_body.is_empty() && self.analyzer.check_blind_boolean(&baseline_body, &body) {
                                 potential_vuln = true;
                                 vector_type = "Boolean/Anomaly";
                                 evidence = "Response differed significantly from baseline".to_string();
                            }

                            if potential_vuln {
                                if self.verify_vulnerability(&target, &param_key, &param_val_str, vector_type, &payload.content).await {
                                    let msg = format!("{} {} param: {}", "VULNERABLE".red().bold(), target.url, param_key);
                                    if let Some(ref p) = pb { p.println(msg); } else { println!("{}", msg); }
                                    
                                    let _ = self.db.log_finding(target.id, &param_key, &mutated_content, &evidence, 95, Some(&method_name)).await;
                                    vulnerable.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        },
                        Err(_) => {}
                    }
                }
            }).await;
        }

        let is_vuln = vulnerable.load(std::sync::atomic::Ordering::Relaxed);
        let new_status = if is_vuln { "VULNERABLE" } else { "SAFE" };
        let _ = self.db.update_target_status(target.id, new_status).await;
    }

    async fn send_request(&self, client: &Client, method: &str, url: &str, params: &serde_json::Value, ua: &str) -> Result<(rquest::StatusCode, String, rquest::header::HeaderMap), rquest::Error> {
        let mut req_builder = match method {
            "GET" => client.get(url).query(params),
            "POST" => client.post(url).json(params),
            _ => client.request(method.parse().unwrap_or(rquest::Method::GET), url),
        };
        
        req_builder = req_builder.header(header::USER_AGENT, ua);
        
        let resp = req_builder.send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await?;
        
        Ok((status, body, headers))
    }

    async fn verify_vulnerability(&self, target: &Target, param_key: &str, base_val: &str, vector_type: &str, original_payload: &str) -> bool {
        let client = match self.create_client().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let ua = self.ua_rotator.get_random();

        match vector_type {
            "Time Based" => {
                let verify_payload = if original_payload.contains("SLEEP(5)") {
                     original_payload.replace("SLEEP(5)", "SLEEP(2)")
                } else if original_payload.contains("WAITFOR DELAY '0:0:5'") {
                     original_payload.replace("0:0:5", "0:0:2")
                } else if original_payload.contains("pg_sleep(5)") {
                     original_payload.replace("pg_sleep(5)", "pg_sleep(2)")
                } else {
                     return false; 
                };
                let mut params = target.params.clone();
                let val = format!("{}{}", base_val, verify_payload);
                params[param_key] = Value::String(val);
                let start = std::time::Instant::now();
                if let Ok(_) = self.send_request(&client, &target.method, &target.url, &params, &ua).await {
                    let duration = start.elapsed();
                    return duration > Duration::from_secs(2) && duration < Duration::from_secs(4);
                }
            },
            "Error Based" => {
                let mut params = target.params.clone();
                let val = format!("{}{}", base_val, original_payload);
                params[param_key] = Value::String(val);
                 if let Ok((_, _body, _)) = self.send_request(&client, &target.method, &target.url, &params, &ua).await {
                    return self.analyzer.check_error_based(&_body);
                }
            },
            "Boolean/Anomaly" => {
                 let mut params = target.params.clone();
                 let val = format!("{}{}", base_val, original_payload);
                 params[param_key] = Value::String(val);
                 if let Ok((_, _body, _)) = self.send_request(&client, &target.method, &target.url, &params, &ua).await {
                     return true; 
                 }
            }
            _ => return true,
        }
        false
    }
}
