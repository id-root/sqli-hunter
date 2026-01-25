use rust_sqli_hunter::waf::WafDetector;
use rquest::header::HeaderMap;

#[test]
fn test_waf_safety_missing_headers() {
    let headers = HeaderMap::new();
    let result = WafDetector::detect(&headers);
    assert_eq!(result, None);
}

#[test]
fn test_waf_safety_normal_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "Apache".parse().unwrap());
    let result = WafDetector::detect(&headers);
    assert_eq!(result, None);
}

#[test]
fn test_waf_detect_cloudflare() {
    let mut headers = HeaderMap::new();
    headers.insert("server", "cloudflare".parse().unwrap());
    let result = WafDetector::detect(&headers);
    assert_eq!(result, Some("Cloudflare".to_string()));
}
