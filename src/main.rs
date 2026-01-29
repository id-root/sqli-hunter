use std::sync::Arc;
use env_logger::Env;
use log::{info, error};
use rust_sqli_hunter::db::Database;
use rust_sqli_hunter::scanner::{Scanner, PayloadStrategy};
use rust_sqli_hunter::cli::Args;
use rust_sqli_hunter::tamper::TamperPipeline;
use rust_sqli_hunter::payloads;
use rust_sqli_hunter::spider::WebSpider;
use rust_sqli_hunter::oob::OOBMonitor;
use rust_sqli_hunter::auth::{AuthMacro, AuthExecutor};
use serde_json::json;
use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader, Write}; 
use indicatif::{ProgressBar, ProgressStyle};
use comfy_table::Table;
use comfy_table::presets::UTF8_FULL;
use colored::*;
use url::Url;
use rquest::cookie::Jar;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();

    println!("{}", r#"
  Orion Suite: Spectre + RustSQLi (Titan Edition)
    "#.cyan().bold());

    let args = Args::parse();

    // ==========================================================================
    // PHASE 0: PRE-SCAN AUTHENTICATION (CRITICAL FIX)
    // ==========================================================================
    // Execute Auth Macro BEFORE scanner initialization to capture session cookies.
    // DVWA returns 302 redirects (not 401) on unauthenticated requests, so we
    // cannot rely on reactive auth challenge handling inside the scanner.
    
    let mut cookie_jar: Option<Arc<Jar>> = None;
    
    // First, check if we have an auth macro to execute upfront
    if let Some(ref macro_path) = args.auth_macro {
        println!("{} {}", "🚀".bright_yellow(), "Executing Auth Macro upfront (pre-scan)...".bright_cyan());
        
        match AuthMacro::from_file(macro_path) {
            Ok(auth_macro) => {
                info!("Loaded auth macro: {} from {}", auth_macro.name, macro_path);
                println!("   Macro: {} - {}", auth_macro.name.green(), 
                         auth_macro.description.as_deref().unwrap_or("No description"));
                
                // Execute auth macro in blocking context (headless_chrome is sync)
                let executor = AuthExecutor::new();
                
                match tokio::task::spawn_blocking(move || {
                    executor.execute(&auth_macro)
                }).await? {
                    Ok(auth_result) => {
                        if auth_result.success {
                            println!("   {} Authentication successful!", "✓".green().bold());
                            println!("   Captured {} session cookies", auth_result.raw_cookies.len());
                            
                            for cookie in &auth_result.raw_cookies {
                                println!("     • {}", cookie.dimmed());
                            }
                            
                            // Store the captured cookies
                            if let Some(jar) = auth_result.cookies {
                                cookie_jar = Some(jar);
                            }
                        } else {
                            let err_msg = auth_result.error.as_deref().unwrap_or("Unknown error");
                            eprintln!("   {} Authentication failed: {}", "✗".red().bold(), err_msg.red());
                            eprintln!("   Continuing without authentication...");
                        }
                    }
                    Err(e) => {
                        error!("Auth macro execution error: {}", e);
                        eprintln!("   {} Auth failed: {}", "✗".red().bold(), e);
                        eprintln!("   Continuing without authentication...");
                    }
                }
            }
            Err(e) => {
                error!("Failed to load auth macro from {}: {}", macro_path, e);
                eprintln!("{} Failed to load auth macro: {}", "ERROR:".red().bold(), e);
            }
        }
        
        println!(); // Blank line for readability
    }
    
    // --- COOKIE PARSING LOGIC (Merge CLI cookies with Auth Macro cookies) ---
    if let Some(cookie_str) = &args.cookie {
        let base_url_str = args.url.as_deref()
            .or(args.domain.as_deref())
            .unwrap_or("http://localhost");
            
        if let Ok(url) = Url::parse(base_url_str) {
            let set_cookie = format!("{}; Domain={}", cookie_str, url.host_str().unwrap_or(""));
            
            // If we already have a jar from auth macro, add to it; otherwise create new
            if let Some(ref jar) = cookie_jar {
                jar.add_cookie_str(&set_cookie, &url);
                println!("Merged CLI cookies with auth session: {}", cookie_str.green());
            } else {
                let jar = Arc::new(Jar::default());
                jar.add_cookie_str(&set_cookie, &url);
                println!("Loaded CLI Cookies: {}", cookie_str.green());
                cookie_jar = Some(jar);
            }
        } else {
            println!("{}", "Warning: Could not associate cookies with a valid URL.".yellow());
        }
    }

    // ==========================================================================
    // DATABASE INITIALIZATION
    // ==========================================================================
    let db_url = "sqlite:fuzzer.db";
    if !std::path::Path::new("fuzzer.db").exists() {
        std::fs::File::create("fuzzer.db")?;
    }
    
    let db = match Database::new(db_url).await {
        Ok(d) => Arc::new(d),
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Ok(());
        }
    };

    if let Err(e) = db.seed_payloads().await {
         error!("Failed to seed payloads: {}", e);
    }

    // ==========================================================================
    // TARGET ACQUISITION PHASE
    // ==========================================================================
    
    // Only add targets if NOT in resume mode
    if !args.resume {
        // 1. Spider Mode
        if let Some(domain_url) = &args.domain {
            info!("Starting Spider on {}", domain_url);
            match Url::parse(domain_url) {
                Ok(spider_scope) => {
                    match rquest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build() 
                    {
                        Ok(client) => {
                            let spider = WebSpider::new(client, db.clone(), spider_scope);
                            spider.crawl(domain_url.clone(), args.depth).await;
                        },
                        Err(e) => error!("Failed to build spider client: {}", e),
                    }
                },
                Err(e) => error!("Invalid domain URL for spider: {}", e),
            }
        }

        // 2. Direct URL Mode
        if let Some(url) = &args.url {
            let params_json = if let Some(p) = &args.params {
                serde_json::from_str(p).unwrap_or(json!({}))
            } else {
                json!({})
            };
            
            info!("Adding target from CLI: {}", url);
            match db.add_target(url, &args.method, params_json).await {
                Ok(_) => {}, // Successfully added
                Err(e) => error!("Could not add target: {}", e),
            }
        }
        
        // ======================================================================
        // CRITICAL FIX: SQLite WAL Sync Delay
        // ======================================================================
        // Allow SQLite Write-Ahead Log (WAL) to sync before querying targets.
        // This prevents race conditions where `get_pending_targets()` returns
        // stale data because the WAL hasn't been checkpointed yet.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        
    } else {
        println!("{}", "Resuming scan from database...".yellow());
    }

    // Load Proxies
    let mut proxies = vec![];
    if let Some(proxy_file) = args.proxy_file {
        if let Ok(file) = File::open(proxy_file) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(l) = line {
                    if !l.trim().is_empty() { proxies.push(l.trim().to_string()); }
                }
            }
            println!("Loaded {} proxies.", proxies.len());
        }
    }

    // Get Pending Targets
    let targets = db.get_pending_targets().await?;

    if targets.is_empty() {
        println!("No pending targets to scan.");
        return Ok(());
    }

    // Load Payloads
    let (payload_strategy, standard_payload_count) = if let Some(path_str) = args.payloads {
         let path = std::path::PathBuf::from(&path_str);
         if let Ok(metadata) = std::fs::metadata(&path) {
             let size = metadata.len();
             if size > 10 * 1024 * 1024 {
                 (PayloadStrategy::Stream(path), 0)
             } else {
                 match payloads::load_payloads_memory(path).await {
                     Ok(p) => {
                         let len = p.len();
                         println!("Loaded {} external payloads.", len);
                         (PayloadStrategy::InMemory(Arc::new(p)), len)
                     },
                     Err(e) => {
                         error!("Failed to load payloads: {}", e);
                         return Ok(());
                     }
                 }
             }
         } else {
             error!("Payload file not found.");
             return Ok(());
         }
    } else {
        let p = db.get_payloads().await?;
        let len = p.len();
        (PayloadStrategy::InMemory(Arc::new(p)), len)
    };

    let oob_count = if args.oob.is_some() { payloads::get_oob_payloads().len() } else { 0 };
    let effective_payload_count = standard_payload_count + oob_count;
    
    let mut total_steps = 0;
    if effective_payload_count > 0 {
        for t in &targets {
            if let Some(obj) = t.params.as_object() {
                total_steps += obj.len() * effective_payload_count;
            }
        }
    }

    let tamper_pipeline = if let Some(t_str) = args.tamper {
        Some(TamperPipeline::from_string(&t_str))
    } else {
        None
    };

    let oob_monitor = if let Some(oob_domain) = args.oob {
        Some(OOBMonitor::new(oob_domain))
    } else {
        None
    };

    // ==========================================================================
    // SCANNER INITIALIZATION (with pre-authenticated cookie jar)
    // ==========================================================================
    let scanner = match Scanner::new(
        db.clone(), 
        args.concurrency, 
        proxies, 
        tamper_pipeline, 
        oob_monitor,
        cookie_jar  // This now contains auth macro cookies if available
    ) {
        Ok(s) => Arc::new(s),
        Err(e) => {
             error!("Failed to initialize scanner: {}", e);
             return Ok(());
        }
    };

    println!("Starting scan against {} targets. (Total requests estimate: {})", 
        targets.len(), 
        if total_steps > 0 { total_steps.to_string() } else { "Unknown (Streaming)".to_string() }
    );

    let pb = Arc::new(ProgressBar::new(total_steps as u64));
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let mut handles = vec![];
    
    for target in targets {
        let scanner = scanner.clone();
        let strategy = payload_strategy.clone();
        let pb = pb.clone();
        
        handles.push(tokio::spawn(async move {
            scanner.scan_target(target, strategy, Some(pb)).await;
        }));
    }

    for handle in handles { let _ = handle.await; }
    
    pb.finish_with_message("Scan Complete");

    println!("\n{}", "Scan Summary".bold().underline());
    
    let findings = db.get_all_findings().await?;
    
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["ID", "Target URL", "Vulnerable Param", "Type", "Confidence"]);

    for finding in &findings {
        table.add_row(vec![
            finding.id.to_string(),
            finding.target_url.clone(),
            finding.vulnerable_param.clone(),
            finding.payload_used.clone(), 
            finding.confidence_score.to_string(),
        ]);
    }

    println!("{table}");

    // --- OUTPUT LOGIC ---
    if let Some(output_path) = args.output {
        println!("Saving findings to {}...", output_path);
        match File::create(output_path) {
            Ok(mut file) => {
                let json_output = serde_json::to_string_pretty(&findings).unwrap_or_default();
                if let Err(e) = file.write_all(json_output.as_bytes()) {
                     error!("Failed to write output file: {}", e);
                } else {
                     println!("{}", "Success!".green());
                }
            },
            Err(e) => error!("Failed to create output file: {}", e),
        }
    }
    
    Ok(())
}
