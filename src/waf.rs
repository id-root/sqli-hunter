use rquest::header::HeaderMap;

pub struct WafDetector;

impl WafDetector {
    pub fn detect(headers: &HeaderMap) -> Option<String> {
        // 1. Check Server Headers
        if let Some(server) = headers.get("server") {
            let s = server.to_str().unwrap_or("").to_lowercase();
            if s.contains("cloudflare") { return Some("Cloudflare".to_string()); }
            if s.contains("akamai") { return Some("Akamai".to_string()); }
            if s.contains("awselb") || s.contains("amazon") { return Some("AWS".to_string()); }
            if s.contains("imperva") { return Some("Imperva".to_string()); }
        }
        
        // 2. Check Specific Headers
        if headers.contains_key("x-amz-cf-id") { return Some("AWS CloudFront".to_string()); }
        if headers.contains_key("cf-ray") { return Some("Cloudflare".to_string()); }
        if headers.contains_key("x-iinfo") { return Some("Imperva".to_string()); }
        
        // 3. Check Cookies (New)
        if let Some(cookie) = headers.get("set-cookie") {
            let c = cookie.to_str().unwrap_or("");
            if c.contains("__cfduid") || c.contains("cf_clearance") { return Some("Cloudflare".to_string()); }
            if c.contains("incap_ses") || c.contains("visid_incap") { return Some("Imperva Incapsula".to_string()); }
            if c.contains("citrix_ns_id") { return Some("Citrix NetScaler".to_string()); }
            if c.contains("datadome") { return Some("DataDome".to_string()); }
        }

        None
    }
}
