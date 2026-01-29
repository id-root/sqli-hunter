// src/daemon/mod.rs
//! Titan Release: gRPC Daemon Mode
//! 
//! Provides a gRPC server for distributed scanning operations.
//! Allows multiple clients to submit jobs, monitor progress, and retrieve findings.

pub mod server;
pub mod job;

pub use server::ScannerDaemon;
pub use job::{Job, JobState, JobManager};

// Include generated protobuf code if available
#[cfg(feature = "grpc")]
pub mod proto {
    tonic::include_proto!("sqli_hunter");
}

// Fallback types when grpc feature is disabled
#[cfg(not(feature = "grpc"))]
pub mod proto {
    /// Placeholder for JobStatus when gRPC is disabled
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum JobStatus {
        Unknown = 0,
        Pending = 1,
        Running = 2,
        Completed = 3,
        Failed = 4,
        Cancelled = 5,
        Paused = 6,
    }
}
