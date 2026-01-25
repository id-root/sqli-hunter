use serde_json::{Value, json};

pub trait Tamper {
    /// Modifies payload or params. Returns true if it handled the injection into params.
    fn tamper(&self, params: &mut Value, key: &str, payload: &mut String) -> bool;
    fn name(&self) -> &str;
}

pub struct Space2Comment;
impl Tamper for Space2Comment {
    fn tamper(&self, _params: &mut Value, _key: &str, payload: &mut String) -> bool {
        *payload = payload.replace(" ", "/**/");
        false
    }
    fn name(&self) -> &str { "Space2Comment" }
}

pub struct Between;
impl Tamper for Between {
    fn tamper(&self, _params: &mut Value, _key: &str, payload: &mut String) -> bool {
        *payload = payload.replace(">", " BETWEEN ");
        false
    }
    fn name(&self) -> &str { "Between" }
}

pub struct HPP;
impl Tamper for HPP {
    fn tamper(&self, params: &mut Value, key: &str, payload: &mut String) -> bool {
        // Get current value
        let current_val = match &params[key] {
             Value::String(s) => s.clone(),
             Value::Number(n) => n.to_string(),
             _ => "".to_string(),
        };
        
        // Construct HPP: Array [current, payload]
        params[key] = json!([current_val, payload]);
        true
    }
    fn name(&self) -> &str { "HPP" }
}

pub struct Chunked;
impl Tamper for Chunked {
    fn tamper(&self, _params: &mut Value, _key: &str, payload: &mut String) -> bool {
        // Simulated chunking (Fragmented)
        *payload = payload.chars().map(|c| format!("{}/**/", c)).collect();
        false
    }
    fn name(&self) -> &str { "Chunked(Simulated)" }
}

pub struct TamperPipeline {
    tampers: Vec<Box<dyn Tamper + Send + Sync>>,
}

impl TamperPipeline {
    pub fn new() -> Self {
        TamperPipeline { tampers: Vec::new() }
    }

    pub fn add(&mut self, tamper: Box<dyn Tamper + Send + Sync>) {
        self.tampers.push(tamper);
    }

    pub fn apply(&self, params: &mut Value, key: &str, original_payload: &str) {
        let mut current_payload = original_payload.to_string();
        let mut handled_injection = false;
        
        for t in &self.tampers {
            if t.tamper(params, key, &mut current_payload) {
                handled_injection = true;
            }
        }
        
        if !handled_injection {
             // Default injection: append payload to existing value
             if let Some(val) = params.get_mut(key) {
                 let old_val = match val {
                     Value::String(s) => s.clone(),
                     Value::Number(n) => n.to_string(),
                     _ => "".to_string(),
                 };
                 *val = Value::String(format!("{}{}", old_val, current_payload));
             }
        }
    }
    
    // Helper to load from CSV list
    pub fn from_string(list: &str) -> Self {
        let mut pipeline = TamperPipeline::new();
        for t in list.split(',') {
            match t.trim() {
                "Space2Comment" => pipeline.add(Box::new(Space2Comment)),
                "Between" => pipeline.add(Box::new(Between)),
                "HPP" => pipeline.add(Box::new(HPP)),
                "Chunked" => pipeline.add(Box::new(Chunked)),
                _ => {},
            }
        }
        pipeline
    }
}
