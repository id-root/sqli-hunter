// src/auth/mod.rs
//! Titan Release: Enterprise Authentication Integration
//! 
//! This module provides authentication macro support for automated login
//! using headless browser automation. It enables scanning of authenticated
//! endpoints by executing YAML-defined login workflows.

pub mod macro_executor;
pub mod session;

pub use macro_executor::{AuthMacro, AuthStep, AuthAction, AuthExecutor, AuthResult};
pub use session::SessionManager;
