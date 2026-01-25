use crate::models::Payload;
use serde_json::Value;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Strategy {
    Integer,
    String,
    Json,
}

pub struct ContextEngine;

impl ContextEngine {
    /// Analyze the parameter value to determine the injection strategy
    pub fn analyze(param_value: &str) -> Strategy {
        // Check for Integer
        if param_value.parse::<i64>().is_ok() {
            return Strategy::Integer;
        }

        // Check for JSON
        if let Ok(_) = serde_json::from_str::<Value>(param_value) {
            let trimmed = param_value.trim();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return Strategy::Json;
            }
        }

        // Default to String
        Strategy::String
    }

    /// Filter and return applicable payloads based on the strategy
    pub fn filter_payloads(payloads: &[Payload], strategy: Strategy) -> Vec<Payload> {
        payloads.iter().filter_map(|p| {
            match strategy {
                Strategy::Integer => {
                    // CRITICAL FIX: Do NOT discard quotes. 
                    // Real-world apps often wrap IDs in quotes (e.g. SELECT * FROM users WHERE id = '$id').
                    // If we remove quotes, we cannot break out of the string literal.
                    Some(p.clone()) 
                },
                Strategy::String => {
                    // For String, we want to try everything.
                    Some(p.clone())
                },
                Strategy::Json => {
                    // For JSON, we preserve all payloads.
                    Some(p.clone())
                }
            }
        }).collect()
    }
}
