// src/ui/mod.rs
//! Titan Release: Terminal User Interface
//! 
//! Provides a rich TUI dashboard for real-time scan monitoring
//! using ratatui for rendering.

pub mod dashboard;
pub mod widgets;

pub use dashboard::{Dashboard, DashboardEvent};
