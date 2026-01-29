pub mod models;
pub mod db;
pub mod scanner;
pub mod evasion;
pub mod utils;
pub mod cli;
pub mod tamper;
pub mod payloads;
pub mod waf;
pub mod calibration;
pub mod spider;
pub mod context;
pub mod oob;

// ========================================
// TITAN RELEASE MODULES
// ========================================

/// Phase 1: Deep Inspection & Logic
pub mod analysis;

/// Phase 2: Enterprise Integration
pub mod auth;
pub mod reporting;

/// Phase 3: Architecture & Scale
pub mod daemon;

/// Phase 4: Reporting & Visualization
pub mod ui;

