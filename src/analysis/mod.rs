// src/analysis/mod.rs
//! Titan Release: Deep Inspection & Logic Module
//! 
//! This module provides structural analysis capabilities for response comparison,
//! eliminating false positives through DOM tree diffing rather than simple string comparison.

pub mod structural;

pub use structural::{StructuralAnalyzer, DiffScore};
