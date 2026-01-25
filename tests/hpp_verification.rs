use rust_sqli_hunter::tamper::{HPP, Tamper};
use serde_json::{json, Value};

#[test]
fn test_hpp_tamper() {
    let mut params = json!({"id": "1"});
    let key = "id";
    let mut payload = "payload".to_string();
    let hpp = HPP;
    
    let result = hpp.tamper(&mut params, key, &mut payload);
    
    assert!(result, "HPP should return true (handled injection)");
    assert_eq!(params["id"], json!(["1", "payload"]));
}

#[test]
fn test_hpp_tamper_number() {
    let mut params = json!({"id": 123});
    let key = "id";
    let mut payload = "payload".to_string();
    let hpp = HPP;
    
    let result = hpp.tamper(&mut params, key, &mut payload);
    
    assert!(result);
    assert_eq!(params["id"], json!(["123", "payload"]));
}
