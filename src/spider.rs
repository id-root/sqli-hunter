use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use rquest::Client;
use url::Url;
use scraper::{Html, Selector};
use crate::db::Database;
use async_recursion::async_recursion;
use serde_json::{Value};
use log::{info, warn, debug};

pub struct WebSpider {
    client: Client,
    visited: Arc<Mutex<HashSet<String>>>,
    db: Arc<Database>,
    scope: Url,
}

impl WebSpider {
    pub fn new(client: Client, db: Arc<Database>, scope: Url) -> Self {
        WebSpider {
            client,
            visited: Arc::new(Mutex::new(HashSet::new())),
            db,
            scope,
        }
    }

    #[async_recursion]
    pub async fn crawl(&self, url_str: String, depth: usize) {
        if depth == 0 {
            return;
        }

        // Deduplication
        {
            let mut visited = self.visited.lock().unwrap();
            if visited.contains(&url_str) {
                return;
            }
            visited.insert(url_str.clone());
        }

        let current_url = match Url::parse(&url_str) {
            Ok(u) => u,
            Err(e) => {
                warn!("Invalid URL {}: {}", url_str, e);
                return;
            }
        };

        // Scope Check
        if let Some(scope_domain) = self.scope.domain() {
            if let Some(curr_domain) = current_url.domain() {
                if scope_domain != curr_domain {
                    debug!("Skipping out of scope: {}", url_str);
                    return;
                }
            } else {
                return;
            }
        } else {
            // If scope has no domain (e.g. IP), strict check
            if current_url.host_str() != self.scope.host_str() {
                return;
            }
        }

        info!("Spider visiting: {}", url_str);

        // Fetch
        let resp = match self.client.get(&url_str).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Spider failed to fetch {}: {}", url_str, e);
                return;
            }
        };

        let html_text = match resp.text().await {
            Ok(t) => t,
            Err(_) => return,
        };

        // --- PHASE 1: PARSING (Sync) ---
        // We extract data into simple owned types (Url, String) so we can drop the !Send types (Html, ElementRef)
        let mut links_to_visit = Vec::new();
        let mut targets_to_add = Vec::new();

        {
            let document = Html::parse_document(&html_text);

            // 1. Extract Links
            if let Ok(link_selector) = Selector::parse("a") {
                for element in document.select(&link_selector) {
                    if let Some(href) = element.value().attr("href") {
                        if let Ok(resolved_url) = current_url.join(href) {
                            // Collect for recursion
                            links_to_visit.push(resolved_url.clone());

                            // Check if it has params for DB
                            if resolved_url.query().is_some() {
                                let mut params_map = serde_json::Map::new();
                                for (k, v) in resolved_url.query_pairs() {
                                    params_map.insert(k.to_string(), Value::String(v.to_string()));
                                }
                                let mut clean_url = resolved_url.clone();
                                clean_url.set_query(None);
                                
                                targets_to_add.push((clean_url.to_string(), "GET".to_string(), Value::Object(params_map)));
                            }
                        }
                    }
                }
            }

            // 2. Extract Forms
            if let Ok(form_selector) = Selector::parse("form") {
                if let Ok(input_selector) = Selector::parse("input, textarea, select") {
                    for element in document.select(&form_selector) {
                        let action = element.value().attr("action").unwrap_or("");
                        let method = element.value().attr("method").unwrap_or("GET").to_uppercase();
                        
                        if let Ok(resolved_action) = current_url.join(action) {
                            let mut params_map = serde_json::Map::new();
                            
                            for input in element.select(&input_selector) {
                                let name = input.value().attr("name");
                                let value = input.value().attr("value").unwrap_or("");
                                if let Some(n) = name {
                                    params_map.insert(n.to_string(), Value::String(value.to_string()));
                                }
                            }

                            if !params_map.is_empty() {
                                let mut clean_url = resolved_action.clone();
                                clean_url.set_query(None);
                                targets_to_add.push((clean_url.to_string(), method, Value::Object(params_map)));
                            }
                        }
                    }
                }
            }
        } // 'document' is dropped here, so !Send types are gone.

        // --- PHASE 2: ACTIONS (Async) ---
        
        // Add Targets to DB
        for (url, method, params) in targets_to_add {
             debug!("Found target: {} [{}]", url, method);
             let _ = self.db.add_target(&url, &method, params).await;
        }

        // Recurse Links
        for link_url in links_to_visit {
             // Scope check again for recursion
             if let Some(d) = link_url.domain() {
                 if let Some(sd) = self.scope.domain() {
                     if d == sd {
                         let _ = self.crawl(link_url.to_string(), depth - 1).await;
                     }
                 }
             }
        }
    }
}
