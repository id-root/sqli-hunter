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
  Orion Suite: Spectre + RustSQLi
    "#.cyan().bold());

    let args = Args::parse();

    // --- COOKIE PARSING LOGIC ---
    let cookie_jar = if let Some(cookie_str) = &args.cookie {
        let jar = Arc::new(Jar::default());
        let base_url_str = args.url.as_deref()
            .or(args.domain.as_deref())
            .unwrap_or("http://localhost");
            
        if let Ok(url) = Url::parse(base_url_str) {
            let set_cookie = format!("{}; Domain={}", cookie_str, url.host_str().unwrap_or(""));
            jar.add_cookie_str(&set_cookie, &url);
            println!("Loaded Cookies: {}", cookie_str.green());
            Some(jar)
        } else {
            println!("{}", "Warning: Could not associate cookies with a valid URL.".yellow());
            None
        }
    } else {
        None
    };

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

    // --- TARGET ACQUISITION PHASE ---
    
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

    let scanner = match Scanner::new(
        db.clone(), 
        args.concurrency, 
        proxies, 
        tamper_pipeline, 
        oob_monitor,
        cookie_jar
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

    // FIX IS HERE: Use &findings to iterate by reference
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
    // Now 'findings' is still available here
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
