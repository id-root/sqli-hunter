// src/reporting/mod.rs
//! Titan Release: Enterprise Reporting Module
//! 
//! Provides multiple output formats for integration with CI/CD pipelines
//! and professional security assessments.

pub mod cicd;
pub mod pdf;

pub use cicd::{SarifReport, JunitReport, ReportFormat};
pub use pdf::PdfReport;
