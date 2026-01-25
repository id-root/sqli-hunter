use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct OOBMonitor {
    oob_domain: String,
    // UUID string -> Target ID
    tracker: Arc<Mutex<HashMap<String, i64>>>,
}

impl OOBMonitor {
    pub fn new(oob_domain: String) -> Self {
        OOBMonitor {
            oob_domain,
            tracker: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generates a unique payload by injecting a UUID and the OOB domain into the template.
    /// Also registers the UUID for tracking.
    pub fn generate_payload(&self, target_id: i64, template: &str) -> String {
        let uuid = Uuid::new_v4().to_string();
        
        // Register tracking
        {
            let mut tracker = self.tracker.lock().unwrap();
            tracker.insert(uuid.clone(), target_id);
        }

        // Replace placeholders
        // Template expected to use <UUID> and <OOB>
        
        let payload = template.replace("<UUID>", &uuid)
                              .replace("<OOB>", &self.oob_domain);
        
        payload
    }
}
