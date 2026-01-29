use rand::Rng;
use urlencoding::encode;
use base64::{Engine as _, engine::general_purpose};

pub enum WafMutation {
    None,
    UrlEncode,
    DoubleUrlEncode,
    SqlComment,
    CaseVariation,
    Base64,
}

pub struct EvasionEngine;

impl EvasionEngine {
    pub fn apply_mutation(payload: &str, mutation: &WafMutation) -> String {
        match mutation {
            WafMutation::None => payload.to_string(),
            WafMutation::UrlEncode => encode(payload).into_owned(),
            WafMutation::DoubleUrlEncode => encode(&encode(payload).into_owned()).into_owned(),
            WafMutation::SqlComment => Self::insert_comments(payload),
            WafMutation::CaseVariation => Self::vary_case(payload),
            WafMutation::Base64 => general_purpose::STANDARD.encode(payload),
        }
    }

    pub fn random_mutation() -> WafMutation {
        let mut rng = rand::thread_rng();
        match rng.gen_range(0..6) {
            0 => WafMutation::None,
            1 => WafMutation::UrlEncode,
            2 => WafMutation::DoubleUrlEncode,
            3 => WafMutation::SqlComment,
            4 => WafMutation::CaseVariation,
            5 => WafMutation::Base64,
            _ => WafMutation::None,
        }
    }
    
    pub fn get_method_name(mutation: &WafMutation) -> String {
        match mutation {
            WafMutation::None => "None".to_string(),
            WafMutation::UrlEncode => "UrlEncode".to_string(),
            WafMutation::DoubleUrlEncode => "DoubleUrlEncode".to_string(),
            WafMutation::SqlComment => "SqlComment".to_string(),
            WafMutation::CaseVariation => "CaseVariation".to_string(),
            WafMutation::Base64 => "Base64".to_string(),
        }
    }

    fn insert_comments(payload: &str) -> String {
        payload.replace(" ", "/**/")
    }

    fn vary_case(payload: &str) -> String {
        let mut rng = rand::thread_rng();
        payload.chars().map(|c| {
            if c.is_alphabetic() && rng.gen_bool(0.5) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        }).collect()
    }
}
