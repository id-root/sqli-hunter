// src/analysis/structural.rs
//! Structural Differential Analysis (SDA) for SQLi Detection
//! 
//! This module implements DOM tree comparison to detect structural changes
//! in HTTP responses that may indicate SQL injection vulnerabilities.
//! Unlike simple string comparison (Levenshtein), this approach:
//! - Ignores dynamic content (timestamps, CSRF tokens, session IDs)
//! - Focuses on structural changes (missing rows, broken elements)
//! - Provides detailed diff scoring for confidence calculation

use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur during structural analysis
#[derive(Error, Debug)]
pub enum StructuralError {
    #[error("Failed to parse HTML: {0}")]
    ParseError(String),
    
    #[error("Analysis failed: {0}")]
    AnalysisError(String),
}

/// Scoring result from DOM tree comparison
#[derive(Debug, Clone, Default)]
pub struct DiffScore {
    /// Normalized delta between 0.0 (identical) and 1.0 (completely different)
    pub structural_delta: f64,
    
    /// Number of nodes present in injected but not in baseline
    pub added_nodes: usize,
    
    /// Number of nodes present in baseline but not in injected
    pub removed_nodes: usize,
    
    /// Number of nodes with different attributes/content
    pub modified_nodes: usize,
    
    /// Total nodes analyzed in baseline
    pub baseline_node_count: usize,
    
    /// Total nodes analyzed in injected response
    pub injected_node_count: usize,
    
    /// Indicates if error-related elements were detected
    pub error_elements_detected: bool,
    
    /// Indicates if table structure changed (strong SQLi indicator)
    pub table_structure_changed: bool,
}

impl DiffScore {
    /// Returns true if the diff suggests a potential vulnerability
    pub fn indicates_vulnerability(&self) -> bool {
        // Strong indicators
        if self.error_elements_detected || self.table_structure_changed {
            return true;
        }
        
        // Significant structural change (>10% difference)
        if self.structural_delta > 0.10 {
            return true;
        }
        
        // Moderate change with node additions/removals
        if self.structural_delta > 0.05 && (self.added_nodes > 3 || self.removed_nodes > 3) {
            return true;
        }
        
        false
    }
    
    /// Returns a confidence score (0-100) based on the diff
    pub fn confidence_score(&self) -> i32 {
        let mut score = 0;
        
        if self.error_elements_detected {
            score += 40;
        }
        
        if self.table_structure_changed {
            score += 30;
        }
        
        // Scale structural delta to score
        score += (self.structural_delta * 30.0).min(30.0) as i32;
        
        score.min(100)
    }
}

/// Structural analyzer for comparing DOM trees
pub struct StructuralAnalyzer {
    /// CSS-like selectors to ignore (dynamic content)
    ignored_patterns: HashSet<String>,
    
    /// Attribute names that indicate dynamic content
    dynamic_attributes: HashSet<String>,
}

impl Default for StructuralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StructuralAnalyzer {
    /// Create a new analyzer with default ignored patterns
    pub fn new() -> Self {
        let mut ignored_patterns = HashSet::new();
        // Common dynamic elements to ignore
        ignored_patterns.insert("csrf".to_string());
        ignored_patterns.insert("token".to_string());
        ignored_patterns.insert("nonce".to_string());
        ignored_patterns.insert("timestamp".to_string());
        ignored_patterns.insert("session".to_string());
        ignored_patterns.insert("captcha".to_string());
        
        let mut dynamic_attributes = HashSet::new();
        dynamic_attributes.insert("data-csrf".to_string());
        dynamic_attributes.insert("data-token".to_string());
        dynamic_attributes.insert("data-nonce".to_string());
        dynamic_attributes.insert("data-timestamp".to_string());
        dynamic_attributes.insert("data-session-id".to_string());
        
        Self {
            ignored_patterns,
            dynamic_attributes,
        }
    }
    
    /// Add a custom pattern to ignore during comparison
    pub fn add_ignored_pattern(&mut self, pattern: &str) {
        self.ignored_patterns.insert(pattern.to_lowercase());
    }
    
    /// Compare two HTML responses and return a diff score
    pub fn compare_dom_trees(&self, baseline: &str, injected: &str) -> Result<DiffScore, StructuralError> {
        let baseline_dom = self.parse_html(baseline)?;
        let injected_dom = self.parse_html(injected)?;
        
        let baseline_sig = self.extract_structural_signature(&baseline_dom.document);
        let injected_sig = self.extract_structural_signature(&injected_dom.document);
        
        self.compute_diff_score(&baseline_sig, &injected_sig, injected)
    }
    
    /// Parse HTML into a DOM tree
    fn parse_html(&self, html: &str) -> Result<RcDom, StructuralError> {
        let dom = parse_document(RcDom::default(), Default::default())
            .from_utf8()
            .read_from(&mut html.as_bytes())
            .map_err(|e| StructuralError::ParseError(e.to_string()))?;
        
        Ok(dom)
    }
    
    /// Extract a structural signature from the DOM for comparison
    fn extract_structural_signature(&self, node: &Handle) -> Vec<NodeSignature> {
        let mut signatures = Vec::new();
        self.collect_signatures(node, &mut signatures, 0);
        signatures
    }
    
    /// Recursively collect node signatures
    fn collect_signatures(&self, node: &Handle, signatures: &mut Vec<NodeSignature>, depth: usize) {
        let data = &node.data;
        
        match data {
            NodeData::Element { name, attrs, .. } => {
                let tag_name = name.local.to_string().to_lowercase();
                
                // Skip if this element should be ignored
                if self.should_ignore_element(&tag_name, &attrs.borrow()) {
                    return;
                }
                
                let attrs_borrowed = attrs.borrow();
                let attr_count = attrs_borrowed.len();
                let has_id = attrs_borrowed.iter().any(|a| a.name.local.to_string() == "id");
                let has_class = attrs_borrowed.iter().any(|a| a.name.local.to_string() == "class");
                
                signatures.push(NodeSignature {
                    tag_name: tag_name.clone(),
                    depth,
                    attribute_count: attr_count,
                    has_id,
                    has_class,
                    is_structural: self.is_structural_element(&tag_name),
                });
            }
            NodeData::Text { contents } => {
                let text = contents.borrow();
                let trimmed = text.trim();
                
                // Only include significant text nodes
                if trimmed.len() > 20 && !self.is_dynamic_text(trimmed) {
                    signatures.push(NodeSignature {
                        tag_name: "#text".to_string(),
                        depth,
                        attribute_count: 0,
                        has_id: false,
                        has_class: false,
                        is_structural: false,
                    });
                }
            }
            _ => {}
        }
        
        // Recurse into children
        for child in node.children.borrow().iter() {
            self.collect_signatures(child, signatures, depth + 1);
        }
    }
    
    /// Check if an element should be ignored based on patterns
    fn should_ignore_element(&self, tag_name: &str, attrs: &[html5ever::Attribute]) -> bool {
        // Check tag name
        for pattern in &self.ignored_patterns {
            if tag_name.contains(pattern) {
                return true;
            }
        }
        
        // Check attributes
        for attr in attrs {
            let attr_name = attr.name.local.to_string().to_lowercase();
            let attr_value = attr.value.to_string().to_lowercase();
            
            // Skip dynamic attributes
            if self.dynamic_attributes.contains(&attr_name) {
                return true;
            }
            
            // Skip elements with dynamic-looking IDs/classes
            if attr_name == "id" || attr_name == "class" {
                for pattern in &self.ignored_patterns {
                    if attr_value.contains(pattern) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Check if text appears to be dynamic (timestamps, UUIDs, etc.)
    fn is_dynamic_text(&self, text: &str) -> bool {
        // UUID pattern
        if text.len() == 36 && text.chars().filter(|c| *c == '-').count() == 4 {
            return true;
        }
        
        // Timestamp patterns
        if text.contains("GMT") || text.contains("UTC") {
            return true;
        }
        
        // ISO 8601 date pattern
        if text.len() >= 10 && text.chars().nth(4) == Some('-') && text.chars().nth(7) == Some('-') {
            return true;
        }
        
        false
    }
    
    /// Check if element is structurally significant for SQLi detection
    fn is_structural_element(&self, tag_name: &str) -> bool {
        matches!(
            tag_name,
            "table" | "tr" | "td" | "th" | "tbody" | "thead" | 
            "ul" | "ol" | "li" | "dl" | "dt" | "dd" |
            "div" | "section" | "article" | "main" | "aside" |
            "form" | "fieldset" | "select" | "option"
        )
    }
    
    /// Compute the diff score between two signatures
    fn compute_diff_score(
        &self,
        baseline: &[NodeSignature],
        injected: &[NodeSignature],
        injected_html: &str,
    ) -> Result<DiffScore, StructuralError> {
        let baseline_set: HashSet<_> = baseline.iter().collect();
        let injected_set: HashSet<_> = injected.iter().collect();
        
        let added: Vec<_> = injected_set.difference(&baseline_set).collect();
        let removed: Vec<_> = baseline_set.difference(&injected_set).collect();
        
        // Count structural elements that changed
        let table_elements_baseline = baseline.iter()
            .filter(|s| s.tag_name == "tr" || s.tag_name == "td")
            .count();
        let table_elements_injected = injected.iter()
            .filter(|s| s.tag_name == "tr" || s.tag_name == "td")
            .count();
        
        let table_structure_changed = if table_elements_baseline > 0 {
            let change_ratio = (table_elements_injected as f64 - table_elements_baseline as f64).abs() 
                / table_elements_baseline as f64;
            change_ratio > 0.1 // More than 10% change in table structure
        } else {
            table_elements_injected > 5 // Significant tables appeared
        };
        
        // Check for error elements in injected response
        let error_elements_detected = self.detect_error_elements(injected_html);
        
        // Calculate structural delta
        let total_unique = baseline_set.len() + injected_set.len();
        let common = baseline_set.intersection(&injected_set).count();
        
        let structural_delta = if total_unique > 0 {
            1.0 - (2.0 * common as f64 / total_unique as f64)
        } else {
            0.0
        };
        
        Ok(DiffScore {
            structural_delta,
            added_nodes: added.len(),
            removed_nodes: removed.len(),
            modified_nodes: 0, // Would require deeper comparison
            baseline_node_count: baseline.len(),
            injected_node_count: injected.len(),
            error_elements_detected,
            table_structure_changed,
        })
    }
    
    /// Detect error-related elements that may indicate SQLi
    fn detect_error_elements(&self, html: &str) -> bool {
        let html_lower = html.to_lowercase();
        
        // SQL error indicators
        let error_indicators = [
            "sql syntax",
            "mysql_fetch",
            "pg_query",
            "ora-",
            "sqlite_",
            "microsoft ole db",
            "odbc driver",
            "syntax error",
            "unclosed quotation",
            "unterminated string",
            "database error",
            "sql error",
            "query failed",
        ];
        
        for indicator in error_indicators {
            if html_lower.contains(indicator) {
                return true;
            }
        }
        
        false
    }
}

/// Structural signature for a DOM node
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NodeSignature {
    tag_name: String,
    depth: usize,
    attribute_count: usize,
    has_id: bool,
    has_class: bool,
    is_structural: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identical_html_returns_zero_delta() {
        let analyzer = StructuralAnalyzer::new();
        let html = r#"<html><body><div id="content"><p>Hello World</p></div></body></html>"#;
        
        let score = analyzer.compare_dom_trees(html, html).unwrap();
        
        assert_eq!(score.structural_delta, 0.0);
        assert_eq!(score.added_nodes, 0);
        assert_eq!(score.removed_nodes, 0);
    }
    
    #[test]
    fn test_different_table_structure_detected() {
        let analyzer = StructuralAnalyzer::new();
        
        let baseline = r#"
            <html><body>
                <table>
                    <tr><td>Row 1</td></tr>
                    <tr><td>Row 2</td></tr>
                </table>
            </body></html>
        "#;
        
        let injected = r#"
            <html><body>
                <table>
                    <tr><td>Row 1</td></tr>
                    <tr><td>Row 2</td></tr>
                    <tr><td>Injected Row</td></tr>
                    <tr><td>Another Row</td></tr>
                    <tr><td>More Data</td></tr>
                </table>
            </body></html>
        "#;
        
        let score = analyzer.compare_dom_trees(baseline, injected).unwrap();
        
        assert!(score.table_structure_changed);
        assert!(score.added_nodes > 0);
    }
    
    #[test]
    fn test_error_elements_detected() {
        let analyzer = StructuralAnalyzer::new();
        
        let baseline = r#"<html><body><p>Normal content</p></body></html>"#;
        let injected = r#"<html><body><p>You have an error in your SQL syntax near...</p></body></html>"#;
        
        let score = analyzer.compare_dom_trees(baseline, injected).unwrap();
        
        assert!(score.error_elements_detected);
        assert!(score.indicates_vulnerability());
    }
    
    #[test]
    fn test_ignores_csrf_tokens() {
        let analyzer = StructuralAnalyzer::new();
        
        let html1 = r#"<html><body><input type="hidden" name="csrf_token" value="abc123"/></body></html>"#;
        let html2 = r#"<html><body><input type="hidden" name="csrf_token" value="xyz789"/></body></html>"#;
        
        let score = analyzer.compare_dom_trees(html1, html2).unwrap();
        
        // CSRF tokens should be ignored, so delta should be minimal
        assert!(score.structural_delta < 0.1);
    }
    
    #[test]
    fn test_confidence_scoring() {
        let score = DiffScore {
            structural_delta: 0.5,
            added_nodes: 10,
            removed_nodes: 5,
            modified_nodes: 3,
            baseline_node_count: 100,
            injected_node_count: 105,
            error_elements_detected: true,
            table_structure_changed: true,
        };
        
        // Should have high confidence with error elements and table changes
        assert!(score.confidence_score() >= 70);
    }
}
