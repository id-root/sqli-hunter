// src/reporting/cicd.rs
//! CI/CD Report Generation
//! 
//! Implements SARIF (Static Analysis Results Interchange Format) and JUnit XML
//! output for integration with CI/CD pipelines like GitHub Actions, GitLab CI, Jenkins.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use chrono::{DateTime, Utc};
use crate::models::Finding;

/// Supported report formats
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReportFormat {
    Json,
    Sarif,
    Junit,
}

impl ReportFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sarif" => ReportFormat::Sarif,
            "junit" | "xml" => ReportFormat::Junit,
            _ => ReportFormat::Json,
        }
    }
    
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Junit => "xml",
        }
    }
}

// ============================================================================
// SARIF 2.1.0 Implementation
// ============================================================================

/// SARIF 2.1.0 compliant report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    /// SARIF schema URL
    #[serde(rename = "$schema")]
    pub schema: String,
    
    /// SARIF version
    pub version: String,
    
    /// Analysis runs
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    /// Tool that produced the results
    pub tool: SarifTool,
    
    /// Analysis results
    pub results: Vec<SarifResult>,
    
    /// Invocation details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

/// SARIF tool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// SARIF driver (scanner) information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    /// Tool name
    pub name: String,
    
    /// Tool version
    pub version: String,
    
    /// Informational URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    
    /// Rule definitions
    pub rules: Vec<SarifRule>,
}

/// SARIF rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    /// Rule ID
    pub id: String,
    
    /// Short description
    pub short_description: SarifMessage,
    
    /// Full description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    
    /// Help text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifHelp>,
    
    /// Default configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifRuleConfig>,
    
    /// Properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

/// SARIF message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

/// SARIF help text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifHelp {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// SARIF rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfig {
    pub level: String, // "error", "warning", "note"
}

/// SARIF rule properties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// SARIF result (finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    /// Rule ID that triggered
    pub rule_id: String,
    
    /// Severity level
    pub level: String,
    
    /// Result message
    pub message: SarifMessage,
    
    /// Locations
    pub locations: Vec<SarifLocation>,
    
    /// Fingerprint for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<SarifFingerprints>,
    
    /// Properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifResultProperties>,
}

/// SARIF location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

/// SARIF physical location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// SARIF artifact location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// SARIF region (for code locations)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

/// SARIF snippet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSnippet {
    pub text: String,
}

/// SARIF fingerprints for dedup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFingerprints {
    pub primary_location_line_hash: String,
}

/// SARIF result properties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResultProperties {
    pub confidence_score: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_bypass_method: Option<String>,
    pub timestamp: String,
}

/// SARIF invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    pub execution_successful: bool,
    pub start_time_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
}

impl SarifReport {
    /// Create a SARIF report from findings
    pub fn from_findings(findings: &[Finding], tool_version: &str) -> Self {
        let rules = vec![
            SarifRule {
                id: "SQLI001".to_string(),
                short_description: SarifMessage {
                    text: "SQL Injection Vulnerability".to_string(),
                },
                full_description: Some(SarifMessage {
                    text: "A SQL injection vulnerability allows attackers to interfere with database queries.".to_string(),
                }),
                help: Some(SarifHelp {
                    text: "Use parameterized queries or prepared statements to prevent SQL injection.".to_string(),
                    markdown: Some("Use **parameterized queries** or **prepared statements** to prevent SQL injection.".to_string()),
                }),
                default_configuration: Some(SarifRuleConfig {
                    level: "error".to_string(),
                }),
                properties: Some(SarifRuleProperties {
                    security_severity: Some("9.8".to_string()),
                    tags: Some(vec!["security".to_string(), "sql-injection".to_string(), "owasp-a03".to_string()]),
                }),
            },
        ];
        
        let results: Vec<SarifResult> = findings.iter().map(|f| {
            SarifResult {
                rule_id: "SQLI001".to_string(),
                level: "error".to_string(),
                message: SarifMessage {
                    text: format!(
                        "SQL Injection found in parameter '{}' at {}",
                        f.vulnerable_param,
                        f.target_url
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.target_url.clone(),
                        },
                        region: Some(SarifRegion {
                            start_line: None,
                            snippet: Some(SarifSnippet {
                                text: f.payload_used.clone(),
                            }),
                        }),
                    },
                }],
                partial_fingerprints: Some(SarifFingerprints {
                    primary_location_line_hash: format!(
                        "{:x}",
                        md5::compute(format!("{}:{}", f.target_url, f.vulnerable_param))
                    ),
                }),
                properties: Some(SarifResultProperties {
                    confidence_score: f.confidence_score,
                    waf_bypass_method: f.waf_bypass_method.clone(),
                    timestamp: f.timestamp.to_string(),
                }),
            }
        }).collect();
        
        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "RustSQLi-Hunter".to_string(),
                        version: tool_version.to_string(),
                        information_uri: Some("https://github.com/sqli-hunter/rust-sqli-hunter".to_string()),
                        rules,
                    },
                },
                results,
                invocations: Some(vec![SarifInvocation {
                    execution_successful: true,
                    start_time_utc: Utc::now().to_rfc3339(),
                    end_time_utc: None,
                }]),
            }],
        }
    }
    
    /// Write report to file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize SARIF report")?;
        
        let mut file = File::create(path.as_ref())
            .context("Failed to create SARIF file")?;
        
        file.write_all(json.as_bytes())
            .context("Failed to write SARIF file")?;
        
        Ok(())
    }
}

// ============================================================================
// JUnit XML Implementation
// ============================================================================

/// JUnit XML report for test framework integration
#[derive(Debug, Clone)]
pub struct JunitReport {
    pub test_suites: Vec<JunitTestSuite>,
    pub timestamp: DateTime<Utc>,
}

/// JUnit test suite
#[derive(Debug, Clone)]
pub struct JunitTestSuite {
    pub name: String,
    pub tests: u32,
    pub failures: u32,
    pub errors: u32,
    pub time: f64,
    pub test_cases: Vec<JunitTestCase>,
}

/// JUnit test case
#[derive(Debug, Clone)]
pub struct JunitTestCase {
    pub name: String,
    pub classname: String,
    pub time: f64,
    pub failure: Option<JunitFailure>,
}

/// JUnit failure
#[derive(Debug, Clone)]
pub struct JunitFailure {
    pub message: String,
    pub failure_type: String,
    pub content: String,
}

impl JunitReport {
    /// Create a JUnit report from findings
    pub fn from_findings(findings: &[Finding], scan_duration_secs: f64) -> Self {
        // Group findings by URL (each URL is a test suite)
        let mut suites_map: std::collections::HashMap<String, Vec<&Finding>> = std::collections::HashMap::new();
        
        for finding in findings {
            suites_map.entry(finding.target_url.clone())
                .or_insert_with(Vec::new)
                .push(finding);
        }
        
        let num_suites = suites_map.len();
        let time_per_suite = if num_suites > 0 { scan_duration_secs / num_suites as f64 } else { 0.0 };
        
        let test_suites: Vec<JunitTestSuite> = suites_map.into_iter().map(|(url, url_findings)| {
            let test_cases: Vec<JunitTestCase> = url_findings.iter().map(|f| {
                JunitTestCase {
                    name: format!("SQLi in param '{}'", f.vulnerable_param),
                    classname: url.clone(),
                    time: 0.0,
                    failure: Some(JunitFailure {
                        message: format!("SQL Injection vulnerability found in parameter '{}'", f.vulnerable_param),
                        failure_type: "SecurityVulnerability".to_string(),
                        content: format!(
                            "Payload: {}\nEvidence: {}\nConfidence: {}%\nWAF Bypass: {}",
                            f.payload_used,
                            f.evidence,
                            f.confidence_score,
                            f.waf_bypass_method.as_deref().unwrap_or("None")
                        ),
                    }),
                }
            }).collect();
            
            JunitTestSuite {
                name: url,
                tests: test_cases.len() as u32,
                failures: test_cases.len() as u32,
                errors: 0,
                time: time_per_suite,
                test_cases,
            }
        }).collect();
        
        JunitReport {
            test_suites,
            timestamp: Utc::now(),
        }
    }
    
    /// Write report to XML file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path.as_ref())
            .context("Failed to create JUnit XML file")?;
        
        // Write XML manually (quick-xml would add complexity)
        writeln!(file, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
        writeln!(file, r#"<testsuites name="RustSQLi-Hunter Security Scan" timestamp="{}">"#, 
                 self.timestamp.to_rfc3339())?;
        
        for suite in &self.test_suites {
            writeln!(file, r#"  <testsuite name="{}" tests="{}" failures="{}" errors="{}" time="{:.3}">"#,
                     xml_escape(&suite.name),
                     suite.tests,
                     suite.failures,
                     suite.errors,
                     suite.time)?;
            
            for test in &suite.test_cases {
                writeln!(file, r#"    <testcase name="{}" classname="{}" time="{:.3}">"#,
                         xml_escape(&test.name),
                         xml_escape(&test.classname),
                         test.time)?;
                
                if let Some(ref failure) = test.failure {
                    writeln!(file, r#"      <failure message="{}" type="{}">"#,
                             xml_escape(&failure.message),
                             xml_escape(&failure.failure_type))?;
                    writeln!(file, "{}", xml_escape(&failure.content))?;
                    writeln!(file, r#"      </failure>"#)?;
                }
                
                writeln!(file, r#"    </testcase>"#)?;
            }
            
            writeln!(file, r#"  </testsuite>"#)?;
        }
        
        writeln!(file, r#"</testsuites>"#)?;
        
        Ok(())
    }
}

/// Escape special XML characters
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Simple MD5 implementation for fingerprinting
mod md5 {
    pub fn compute(input: String) -> impl std::fmt::LowerHex {
        // Simple hash for fingerprinting - not cryptographically secure
        let mut hash: u128 = 0;
        for (i, byte) in input.bytes().enumerate() {
            hash = hash.wrapping_add((byte as u128) << ((i % 16) * 8));
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;
    
    fn create_test_findings() -> Vec<Finding> {
        vec![
            Finding {
                id: 1,
                target_id: 1,
                target_url: "http://test.com/api".to_string(),
                vulnerable_param: "id".to_string(),
                payload_used: "' OR 1=1--".to_string(),
                evidence: "SQL syntax error".to_string(),
                confidence_score: 95,
                waf_bypass_method: Some("Space2Comment".to_string()),
                timestamp: NaiveDateTime::from_timestamp_opt(1706500000, 0).unwrap(),
            },
        ]
    }
    
    #[test]
    fn test_sarif_report_generation() {
        let findings = create_test_findings();
        let report = SarifReport::from_findings(&findings, "5.0.0");
        
        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "SQLI001");
    }
    
    #[test]
    fn test_junit_report_generation() {
        let findings = create_test_findings();
        let report = JunitReport::from_findings(&findings, 10.0);
        
        assert_eq!(report.test_suites.len(), 1);
        assert_eq!(report.test_suites[0].failures, 1);
    }
    
    #[test]
    fn test_report_format_parsing() {
        assert_eq!(ReportFormat::from_str("sarif"), ReportFormat::Sarif);
        assert_eq!(ReportFormat::from_str("SARIF"), ReportFormat::Sarif);
        assert_eq!(ReportFormat::from_str("junit"), ReportFormat::Junit);
        assert_eq!(ReportFormat::from_str("xml"), ReportFormat::Junit);
        assert_eq!(ReportFormat::from_str("json"), ReportFormat::Json);
        assert_eq!(ReportFormat::from_str("unknown"), ReportFormat::Json);
    }
    
    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape(r#"a"b"#), "a&quot;b");
    }
}
