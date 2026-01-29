// src/context.rs
//! Context Engine with SQL AST Parsing
//! 
//! Titan Release: Upgraded from simple type detection to full SQL AST parsing
//! using sqlparser to detect injection zones (WHERE, ORDER BY, LIMIT, INSERT).

use crate::models::Payload;
use serde_json::Value;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;


/// Original strategy for payload type selection
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Strategy {
    Integer,
    String,
    Json,
}

/// Represents the detected SQL injection zone
/// Used to select more targeted payloads for specific SQL contexts
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum InjectionZone {
    /// Value is likely in a WHERE clause condition
    WhereClause,
    /// Value is likely in an ORDER BY clause
    OrderBy,
    /// Value is likely in a LIMIT/OFFSET clause
    Limit,
    /// Value is likely in an INSERT VALUES clause
    InsertValues,
    /// Value is likely in a column selection (SELECT x, y, z)
    SelectColumn,
    /// Value is likely in a UNION context
    Union,
    /// Could not determine the injection zone
    Unknown,
}

impl InjectionZone {
    /// Returns a human-readable description of the injection zone
    pub fn description(&self) -> &'static str {
        match self {
            InjectionZone::WhereClause => "WHERE clause condition",
            InjectionZone::OrderBy => "ORDER BY clause",
            InjectionZone::Limit => "LIMIT/OFFSET clause",
            InjectionZone::InsertValues => "INSERT VALUES",
            InjectionZone::SelectColumn => "SELECT column list",
            InjectionZone::Union => "UNION context",
            InjectionZone::Unknown => "Unknown context",
        }
    }
    
    /// Returns recommended payload types for this zone
    pub fn recommended_vectors(&self) -> Vec<&'static str> {
        match self {
            InjectionZone::WhereClause => vec![
                "Boolean Based",
                "Error Based", 
                "Time Based",
                "UNION Based",
            ],
            InjectionZone::OrderBy => vec![
                "Order By Injection",
                "Error Based",
                "Time Based",
            ],
            InjectionZone::Limit => vec![
                "Limit Injection",
                "Error Based",
            ],
            InjectionZone::InsertValues => vec![
                "Insert Injection",
                "Error Based",
                "Time Based",
            ],
            InjectionZone::SelectColumn => vec![
                "Column Injection",
                "UNION Based",
            ],
            InjectionZone::Union => vec![
                "UNION Based",
                "Error Based",
            ],
            InjectionZone::Unknown => vec![
                "Boolean Based",
                "Error Based",
                "Time Based",
            ],
        }
    }
}

/// Analysis result from the context engine
#[derive(Debug, Clone)]
pub struct ContextAnalysis {
    /// The basic strategy (Integer, String, Json)
    pub strategy: Strategy,
    /// The detected injection zone
    pub zone: InjectionZone,
    /// Confidence in the zone detection (0.0 - 1.0)
    pub zone_confidence: f64,
    /// Original value analyzed
    pub original_value: String,
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
    
    /// Perform comprehensive analysis including injection zone detection
    pub fn analyze_comprehensive(param_value: &str) -> ContextAnalysis {
        let strategy = Self::analyze(param_value);
        let (zone, confidence) = Self::detect_injection_zone(param_value);
        
        ContextAnalysis {
            strategy,
            zone,
            zone_confidence: confidence,
            original_value: param_value.to_string(),
        }
    }
    
    /// Attempt to parse SQL fragment and detect injection zone
    /// Returns the detected zone and a confidence score
    pub fn detect_injection_zone(fragment: &str) -> (InjectionZone, f64) {
        let dialect = GenericDialect {};
        
        // Strategy: Try wrapping the fragment in various SQL contexts
        // and see which one parses successfully
        
        // Test 1: Is it a value in a WHERE clause?
        let where_test = format!("SELECT * FROM t WHERE col = {}", fragment);
        if Self::try_parse(&dialect, &where_test) {
            return (InjectionZone::WhereClause, 0.9);
        }
        
        // Test 2: Quoted string in WHERE clause
        let where_string_test = format!("SELECT * FROM t WHERE col = '{}'", fragment);
        if Self::try_parse(&dialect, &where_string_test) {
            return (InjectionZone::WhereClause, 0.85);
        }
        
        // Test 3: Is it an ORDER BY column?
        let order_test = format!("SELECT * FROM t ORDER BY {}", fragment);
        if Self::try_parse(&dialect, &order_test) {
            return (InjectionZone::OrderBy, 0.8);
        }
        
        // Test 4: Is it a LIMIT value?
        let limit_test = format!("SELECT * FROM t LIMIT {}", fragment);
        if Self::try_parse(&dialect, &limit_test) {
            // Additional check: should be numeric
            if fragment.parse::<i64>().is_ok() {
                return (InjectionZone::Limit, 0.9);
            }
            return (InjectionZone::Limit, 0.7);
        }
        
        // Test 5: Could it be part of INSERT VALUES?
        let insert_test = format!("INSERT INTO t (col) VALUES ({})", fragment);
        if Self::try_parse(&dialect, &insert_test) {
            return (InjectionZone::InsertValues, 0.75);
        }
        
        // Test 6: Could it be a column name?
        let column_test = format!("SELECT {} FROM t", fragment);
        if Self::try_parse(&dialect, &column_test) {
            // Check if it looks like a valid identifier
            if Self::is_valid_identifier(fragment) {
                return (InjectionZone::SelectColumn, 0.7);
            }
        }
        
        // Heuristic fallback based on value characteristics
        Self::heuristic_zone_detection(fragment)
    }
    
    /// Try to parse a SQL statement
    fn try_parse(dialect: &GenericDialect, sql: &str) -> bool {
        Parser::parse_sql(dialect, sql).is_ok()
    }
    
    /// Check if string could be a valid SQL identifier
    fn is_valid_identifier(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        
        let first = s.chars().next().unwrap();
        if !first.is_alphabetic() && first != '_' {
            return false;
        }
        
        s.chars().all(|c| c.is_alphanumeric() || c == '_')
    }
    
    /// Heuristic-based zone detection when parsing fails
    fn heuristic_zone_detection(fragment: &str) -> (InjectionZone, f64) {
        let fragment_lower = fragment.to_lowercase();
        
        // Check for ORDER BY indicators
        if fragment_lower.contains("asc") || fragment_lower.contains("desc") {
            return (InjectionZone::OrderBy, 0.5);
        }
        
        // Check for LIMIT-like values
        if fragment.parse::<i64>().is_ok() {
            let val: i64 = fragment.parse().unwrap();
            // Small positive integers are often LIMIT/pagination values
            if val > 0 && val < 1000 {
                return (InjectionZone::Limit, 0.4);
            }
            // Larger integers might be IDs in WHERE clauses
            return (InjectionZone::WhereClause, 0.5);
        }
        
        // Check for UNION indicators
        if fragment_lower.contains("union") || fragment_lower.contains("select") {
            return (InjectionZone::Union, 0.6);
        }
        
        // Default: assume WHERE clause (most common)
        (InjectionZone::Unknown, 0.3)
    }
    
    /// Analyze the actual SQL structure if we can find it in the response
    /// This is an advanced technique that parses SQL errors to determine context
    pub fn analyze_error_context(error_message: &str) -> Option<InjectionZone> {
        let error_lower = error_message.to_lowercase();
        
        // Look for SQL keywords that indicate context
        if error_lower.contains("where") && error_lower.contains("syntax") {
            return Some(InjectionZone::WhereClause);
        }
        
        if error_lower.contains("order by") {
            return Some(InjectionZone::OrderBy);
        }
        
        if error_lower.contains("limit") || error_lower.contains("offset") {
            return Some(InjectionZone::Limit);
        }
        
        if error_lower.contains("insert") || error_lower.contains("values") {
            return Some(InjectionZone::InsertValues);
        }
        
        if error_lower.contains("union") {
            return Some(InjectionZone::Union);
        }
        
        None
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
    
    /// Filter payloads based on injection zone (more targeted than strategy)
    pub fn filter_payloads_by_zone(payloads: &[Payload], zone: InjectionZone) -> Vec<Payload> {
        let recommended = zone.recommended_vectors();
        
        payloads.iter().filter(|p| {
            // Include if vector type matches recommended, or if zone is Unknown (try everything)
            zone == InjectionZone::Unknown || 
            recommended.iter().any(|r| p.vector_type.contains(r))
        }).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_analyze_integer() {
        assert_eq!(ContextEngine::analyze("123"), Strategy::Integer);
        assert_eq!(ContextEngine::analyze("-456"), Strategy::Integer);
        assert_eq!(ContextEngine::analyze("0"), Strategy::Integer);
    }
    
    #[test]
    fn test_analyze_string() {
        assert_eq!(ContextEngine::analyze("hello"), Strategy::String);
        assert_eq!(ContextEngine::analyze("hello world"), Strategy::String);
        assert_eq!(ContextEngine::analyze("12.34.56"), Strategy::String);
    }
    
    #[test]
    fn test_analyze_json() {
        assert_eq!(ContextEngine::analyze(r#"{"key": "value"}"#), Strategy::Json);
        assert_eq!(ContextEngine::analyze(r#"[1, 2, 3]"#), Strategy::Json);
    }
    
    #[test]
    fn test_detect_where_clause() {
        let (zone, confidence) = ContextEngine::detect_injection_zone("123");
        // Numeric values in WHERE clauses should be detected
        assert!(confidence > 0.0);
    }
    
    #[test]
    fn test_detect_order_by() {
        // Test with column-like value
        let (zone, _) = ContextEngine::detect_injection_zone("name");
        // Could be ORDER BY or SELECT column
        assert!(zone == InjectionZone::OrderBy || zone == InjectionZone::SelectColumn || zone == InjectionZone::Unknown);
    }
    
    #[test]
    fn test_detect_limit() {
        let (zone, confidence) = ContextEngine::detect_injection_zone("10");
        // Small integers are often LIMIT values
        assert!(zone == InjectionZone::Limit || zone == InjectionZone::WhereClause);
        assert!(confidence > 0.3);
    }
    
    #[test]
    fn test_analyze_error_context() {
        let error = "You have an error in your SQL syntax near ORDER BY";
        let zone = ContextEngine::analyze_error_context(error);
        assert_eq!(zone, Some(InjectionZone::OrderBy));
    }
    
    #[test]
    fn test_injection_zone_recommendations() {
        let where_recs = InjectionZone::WhereClause.recommended_vectors();
        assert!(where_recs.contains(&"Boolean Based"));
        assert!(where_recs.contains(&"UNION Based"));
        
        let order_recs = InjectionZone::OrderBy.recommended_vectors();
        assert!(order_recs.contains(&"Order By Injection"));
    }
    
    #[test]
    fn test_comprehensive_analysis() {
        let analysis = ContextEngine::analyze_comprehensive("42");
        assert_eq!(analysis.strategy, Strategy::Integer);
        assert_eq!(analysis.original_value, "42");
    }
}
