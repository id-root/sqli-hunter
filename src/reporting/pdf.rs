// src/reporting/pdf.rs
//! PDF Report Generation
//! 
//! Creates professional security assessment reports in PDF format
//! with Executive Summary, Vulnerability Details, and Remediation Steps.

use anyhow::{Context, Result};
use genpdf::{Document, Element, Alignment};
use genpdf::elements::{Paragraph, Break};
use genpdf::style::Style;
use std::path::Path;
use chrono::{DateTime, Utc};
use crate::models::Finding;

/// Scan metadata for report generation
#[derive(Debug, Clone)]
pub struct ScanMetadata {
    /// When the scan was performed
    pub scan_date: DateTime<Utc>,
    
    /// Number of targets scanned
    pub target_count: usize,
    
    /// Total scan duration
    pub duration_secs: f64,
    
    /// Tool version
    pub tool_version: String,
    
    /// Scan mode used
    pub scan_mode: String,
    
    /// Safety level used
    pub safety_level: u8,
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            scan_date: Utc::now(),
            target_count: 0,
            duration_secs: 0.0,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_mode: "Standard".to_string(),
            safety_level: 3,
        }
    }
}

/// PDF report generator for security assessments
pub struct PdfReport {
    /// Findings to include in the report
    findings: Vec<Finding>,
    
    /// Scan metadata
    metadata: ScanMetadata,
    
    /// Report title
    title: String,
    
    /// Organization/client name
    client_name: Option<String>,
}

impl PdfReport {
    /// Create a new PDF report
    pub fn new(findings: Vec<Finding>, metadata: ScanMetadata) -> Self {
        Self {
            findings,
            metadata,
            title: "SQL Injection Security Assessment".to_string(),
            client_name: None,
        }
    }
    
    /// Set custom report title
    pub fn with_title(mut self, title: &str) -> Self {
        self.title = title.to_string();
        self
    }
    
    /// Set client name
    pub fn with_client(mut self, name: &str) -> Self {
        self.client_name = Some(name.to_string());
        self
    }
    
    /// Generate the PDF report
    pub fn generate<P: AsRef<Path>>(&self, output_path: P) -> Result<()> {
        // Try to load fonts from system or use fallback
        let font_family = genpdf::fonts::from_files("./fonts", "LiberationSans", None)
            .or_else(|_| genpdf::fonts::from_files("/usr/share/fonts/truetype/liberation", "LiberationSans", None))
            .context("Failed to load fonts. Please install Liberation fonts.")?;
        
        let mut doc = Document::new(font_family);
        doc.set_title(&self.title);
        // Note: genpdf 0.2 handles margins via page decorator or defaults
        
        // Title page
        self.add_title_page(&mut doc);
        
        // Executive Summary
        self.add_executive_summary(&mut doc);
        
        // Vulnerability Details
        self.add_vulnerability_details(&mut doc);
        
        // Remediation Steps
        self.add_remediation_section(&mut doc);
        
        // Appendix
        self.add_appendix(&mut doc);
        
        // Render to file
        doc.render_to_file(output_path.as_ref())
            .context("Failed to render PDF report")?;
        
        Ok(())
    }
    
    /// Add title page
    fn add_title_page(&self, doc: &mut Document) {
        let title_style = Style::new().bold().with_font_size(24);
        let subtitle_style = Style::new().with_font_size(14);
        
        // Add spacing
        doc.push(Break::new(5));
        
        // Title - styled first, then aligned
        doc.push(Paragraph::new(&self.title).aligned(Alignment::Center).styled(title_style));
        
        doc.push(Break::new(1));
        
        // Subtitle
        doc.push(Paragraph::new("RustSQLi-Hunter Security Scan Report")
            .aligned(Alignment::Center)
            .styled(subtitle_style));
        
        doc.push(Break::new(2));
        
        // Client name if provided
        if let Some(ref client) = self.client_name {
            doc.push(Paragraph::new(format!("Prepared for: {}", client))
                .aligned(Alignment::Center)
                .styled(subtitle_style));
        }
        
        doc.push(Break::new(1));
        
        // Date
        doc.push(Paragraph::new(format!("Date: {}", self.metadata.scan_date.format("%Y-%m-%d")))
            .aligned(Alignment::Center));
        
        doc.push(Break::new(3));
        
        // Summary stats box
        let stats = format!(
            "Targets Scanned: {} | Vulnerabilities Found: {} | Duration: {:.1}s",
            self.metadata.target_count,
            self.findings.len(),
            self.metadata.duration_secs
        );
        doc.push(Paragraph::new(stats).aligned(Alignment::Center));
    }
    
    /// Add executive summary section
    fn add_executive_summary(&self, doc: &mut Document) {
        let section_style = Style::new().bold().with_font_size(16);
        let text_style = Style::new().with_font_size(10);
        
        doc.push(Break::new(2));
        
        // Section header
        doc.push(Paragraph::new("EXECUTIVE SUMMARY").styled(section_style));
        doc.push(Break::new(1));
        
        // Overview
        let severity = if self.findings.is_empty() {
            "No SQL injection vulnerabilities were identified."
        } else if self.findings.len() == 1 {
            "One SQL injection vulnerability was identified, requiring immediate attention."
        } else {
            "Multiple SQL injection vulnerabilities were identified, requiring immediate remediation."
        };
        
        doc.push(Paragraph::new(severity).styled(text_style));
        doc.push(Break::new(1));
        
        // Risk summary
        let high_conf = self.findings.iter().filter(|f| f.confidence_score >= 90).count();
        let med_conf = self.findings.iter().filter(|f| f.confidence_score >= 70 && f.confidence_score < 90).count();
        let low_conf = self.findings.iter().filter(|f| f.confidence_score < 70).count();
        
        let risk_text = format!(
            "Risk Assessment:\n  - High Confidence: {} vulnerabilities\n  - Medium Confidence: {} vulnerabilities\n  - Low Confidence: {} vulnerabilities",
            high_conf, med_conf, low_conf
        );
        doc.push(Paragraph::new(risk_text).styled(text_style));
        
        doc.push(Break::new(1));
        
        // Key findings
        if !self.findings.is_empty() {
            doc.push(Paragraph::new("Key Findings:").styled(Style::new().bold().with_font_size(11)));
            
            for (i, finding) in self.findings.iter().take(5).enumerate() {
                let finding_text = format!(
                    "{}. {} - Parameter '{}' (Confidence: {}%)",
                    i + 1,
                    finding.target_url,
                    finding.vulnerable_param,
                    finding.confidence_score
                );
                doc.push(Paragraph::new(finding_text).styled(text_style));
            }
            
            if self.findings.len() > 5 {
                let more = format!("... and {} more vulnerabilities detailed below.", self.findings.len() - 5);
                doc.push(Paragraph::new(more).styled(text_style));
            }
        }
    }
    
    /// Add detailed vulnerability information
    fn add_vulnerability_details(&self, doc: &mut Document) {
        let section_style = Style::new().bold().with_font_size(16);
        let subsection_style = Style::new().bold().with_font_size(12);
        let text_style = Style::new().with_font_size(10);
        let code_style = Style::new().with_font_size(9);
        
        doc.push(Break::new(2));
        doc.push(Paragraph::new("VULNERABILITY DETAILS").styled(section_style));
        
        if self.findings.is_empty() {
            doc.push(Break::new(1));
            doc.push(Paragraph::new("No vulnerabilities were identified during this scan.").styled(text_style));
            return;
        }
        
        for (i, finding) in self.findings.iter().enumerate() {
            doc.push(Break::new(1));
            
            // Finding header
            let header = format!("Finding #{}: SQL Injection", i + 1);
            doc.push(Paragraph::new(header).styled(subsection_style));
            
            // Details
            doc.push(Paragraph::new(format!("Target URL: {}", finding.target_url)).styled(text_style));
            doc.push(Paragraph::new(format!("Vulnerable Parameter: {}", finding.vulnerable_param)).styled(text_style));
            doc.push(Paragraph::new(format!("Confidence Score: {}%", finding.confidence_score)).styled(text_style));
            doc.push(Paragraph::new(format!("WAF Bypass: {}", finding.waf_bypass_method.as_deref().unwrap_or("None"))).styled(text_style));
            doc.push(Paragraph::new(format!("Detected: {}", finding.timestamp)).styled(text_style));
            
            // Payload used
            doc.push(Paragraph::new("Payload Used:").styled(Style::new().bold().with_font_size(10)));
            let payload = if finding.payload_used.len() > 100 {
                format!("{}...", &finding.payload_used[..100])
            } else {
                finding.payload_used.clone()
            };
            doc.push(Paragraph::new(payload).styled(code_style));
            
            // Evidence
            doc.push(Paragraph::new("Evidence:").styled(Style::new().bold().with_font_size(10)));
            let evidence = if finding.evidence.len() > 200 {
                format!("{}...", &finding.evidence[..200])
            } else {
                finding.evidence.clone()
            };
            doc.push(Paragraph::new(evidence).styled(code_style));
        }
    }
    
    /// Add remediation recommendations
    fn add_remediation_section(&self, doc: &mut Document) {
        let section_style = Style::new().bold().with_font_size(16);
        let subsection_style = Style::new().bold().with_font_size(12);
        let text_style = Style::new().with_font_size(10);
        
        doc.push(Break::new(2));
        doc.push(Paragraph::new("REMEDIATION RECOMMENDATIONS").styled(section_style));
        doc.push(Break::new(1));
        
        // General recommendations
        let recommendations = [
            ("1. Use Parameterized Queries", "Replace all dynamic SQL concatenation with parameterized queries or prepared statements. This is the most effective defense against SQL injection."),
            ("2. Input Validation", "Implement strict input validation using allowlists. Validate data types, length, format, and range before processing."),
            ("3. Least Privilege Database Access", "Configure database accounts with minimal required permissions. Web applications should not use accounts with administrative privileges."),
            ("4. Web Application Firewall (WAF)", "Deploy a WAF as an additional layer of defense. Note that WAFs can be bypassed and should not be the sole protection mechanism."),
            ("5. Error Handling", "Implement custom error pages that do not expose database error messages or stack traces to end users."),
            ("6. Regular Security Testing", "Conduct regular security assessments including automated scanning and manual penetration testing to identify new vulnerabilities."),
        ];
        
        for (title, description) in &recommendations {
            doc.push(Paragraph::new(*title).styled(subsection_style));
            doc.push(Paragraph::new(*description).styled(text_style));
        }
    }
    
    /// Add appendix with scan details
    fn add_appendix(&self, doc: &mut Document) {
        let section_style = Style::new().bold().with_font_size(16);
        let text_style = Style::new().with_font_size(9);
        
        doc.push(Break::new(2));
        doc.push(Paragraph::new("APPENDIX: SCAN CONFIGURATION").styled(section_style));
        doc.push(Break::new(1));
        
        let config_items = vec![
            format!("Tool Version: RustSQLi-Hunter v{}", self.metadata.tool_version),
            format!("Scan Mode: {}", self.metadata.scan_mode),
            format!("Safety Level: {}/5", self.metadata.safety_level),
            format!("Targets Scanned: {}", self.metadata.target_count),
            format!("Total Duration: {:.2} seconds", self.metadata.duration_secs),
            format!("Report Generated: {}", Utc::now().to_rfc3339()),
        ];
        
        for item in config_items {
            doc.push(Paragraph::new(item).styled(text_style));
        }
        
        doc.push(Break::new(1));
        
        // Disclaimer
        doc.push(Paragraph::new("DISCLAIMER").styled(Style::new().bold().with_font_size(10)));
        doc.push(Paragraph::new(
            "This report is provided for informational purposes only. The findings represent \
             the state of the application at the time of testing and may not reflect its \
             current security posture. False positives are possible and should be manually verified."
        ).styled(text_style));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_pdf_report() {
        let metadata = ScanMetadata {
            scan_date: Utc::now(),
            target_count: 5,
            duration_secs: 120.5,
            tool_version: "5.0.0".to_string(),
            scan_mode: "Standard".to_string(),
            safety_level: 3,
        };
        
        let report = PdfReport::new(vec![], metadata)
            .with_title("Test Security Assessment")
            .with_client("ACME Corp");
        
        assert_eq!(report.title, "Test Security Assessment");
        assert_eq!(report.client_name, Some("ACME Corp".to_string()));
    }
}
