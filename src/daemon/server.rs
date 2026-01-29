// src/daemon/server.rs
//! gRPC Server Implementation
//! 
//! Implements the ScannerService for distributed scanning operations.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use log::{info, warn, error};
use chrono::Utc;

use super::job::{Job, JobConfig, JobManager, JobState, JobStatus};

/// Scanner daemon server
pub struct ScannerDaemon {
    /// Job manager
    job_manager: Arc<JobManager>,
    
    /// Server start time
    start_time: Instant,
    
    /// Server version
    version: String,
    
    /// Server address
    address: String,
    
    /// Shutdown signal sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ScannerDaemon {
    /// Create a new scanner daemon
    pub fn new(max_concurrent_jobs: usize) -> Self {
        Self {
            job_manager: Arc::new(JobManager::new(max_concurrent_jobs)),
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            address: "127.0.0.1:50051".to_string(),
            shutdown_tx: None,
        }
    }
    
    /// Set the server address
    pub fn with_address(mut self, address: &str) -> Self {
        self.address = address.to_string();
        self
    }
    
    /// Get the job manager
    pub fn job_manager(&self) -> Arc<JobManager> {
        self.job_manager.clone()
    }
    
    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
    
    /// Get server version
    pub fn version(&self) -> &str {
        &self.version
    }
    
    /// Submit a new scan job
    pub async fn submit_job(&self, config: JobConfig) -> Result<(String, i32)> {
        let job_id = self.job_manager.submit(config).await?;
        let queue_pos = self.job_manager.queue_size().await as i32;
        
        Ok((job_id, queue_pos))
    }
    
    /// Get job status
    pub async fn get_job_status(&self, job_id: &str) -> Option<JobStatusResponse> {
        let job = self.job_manager.get(job_id).await?;
        let job = job.lock().await;
        let state = job.get_state().await;
        
        Some(JobStatusResponse {
            job_id: job_id.to_string(),
            status: state.status,
            progress_percent: state.progress_percent,
            findings_count: state.findings_count,
            current_target: state.current_target,
            payloads_tested: state.payloads_tested,
            total_payloads: state.total_payloads,
            error: state.error,
            started_at: job.started_at.map(|t| t.to_rfc3339()),
            completed_at: job.completed_at.map(|t| t.to_rfc3339()),
        })
    }
    
    /// Stop a job
    pub async fn stop_job(&self, job_id: &str, force: bool) -> Result<JobStatus> {
        self.job_manager.stop(job_id, force).await
    }
    
    /// List jobs
    pub async fn list_jobs(
        &self,
        status_filter: Option<JobStatus>,
        limit: usize,
        offset: usize,
    ) -> Vec<JobSummary> {
        self.job_manager
            .list(status_filter, limit, offset)
            .await
            .into_iter()
            .map(|(id, state)| JobSummary {
                job_id: id,
                status: state.status,
                progress_percent: state.progress_percent,
                findings_count: state.findings_count,
            })
            .collect()
    }
    
    /// Health check
    pub async fn health_check(&self) -> HealthStatus {
        HealthStatus {
            healthy: true,
            version: self.version.clone(),
            active_jobs: self.job_manager.active_count().await as i32,
            queue_size: self.job_manager.queue_size().await as i32,
            uptime_seconds: self.uptime_seconds() as i64,
        }
    }
    
    /// Start the daemon server (non-gRPC version for testing)
    pub async fn serve(&mut self) -> Result<()> {
        info!("Starting Scanner Daemon on {}", self.address);
        
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);
        
        // In the full implementation, this would start a tonic server
        // For now, we just wait for shutdown signal
        info!("Scanner Daemon ready. Waiting for jobs...");
        
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    // Periodic health log
                    let health = self.health_check().await;
                    info!(
                        "Daemon status: {} active jobs, {} queued, uptime {}s",
                        health.active_jobs,
                        health.queue_size,
                        health.uptime_seconds
                    );
                }
            }
        }
        
        info!("Scanner Daemon shutdown complete");
        Ok(())
    }
    
    /// Request daemon shutdown
    pub async fn shutdown(&self) -> bool {
        if let Some(ref tx) = self.shutdown_tx {
            tx.send(()).await.is_ok()
        } else {
            false
        }
    }
}

/// Job status response
#[derive(Debug, Clone)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub status: JobStatus,
    pub progress_percent: i32,
    pub findings_count: i32,
    pub current_target: String,
    pub payloads_tested: i64,
    pub total_payloads: i64,
    pub error: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Job summary for listing
#[derive(Debug, Clone)]
pub struct JobSummary {
    pub job_id: String,
    pub status: JobStatus,
    pub progress_percent: i32,
    pub findings_count: i32,
}

/// Health status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub version: String,
    pub active_jobs: i32,
    pub queue_size: i32,
    pub uptime_seconds: i64,
}

// ============================================================================
// gRPC Service Implementation (when tonic is available)
// ============================================================================

#[cfg(feature = "grpc")]
mod grpc_impl {
    use super::*;
    use tonic::{Request, Response, Status};
    use crate::daemon::proto::scanner_service_server::ScannerService;
    use crate::daemon::proto::*;
    
    #[tonic::async_trait]
    impl ScannerService for ScannerDaemon {
        async fn submit_job(
            &self,
            request: Request<SubmitJobRequest>,
        ) -> Result<Response<SubmitJobResponse>, Status> {
            let req = request.into_inner();
            
            let config = JobConfig {
                url: req.url,
                method: req.method,
                params_json: req.params_json,
                safety_level: req.safety_level as u8,
                concurrency: req.concurrency as usize,
                proxies: if req.proxies.is_empty() {
                    vec![]
                } else {
                    req.proxies.split(',').map(|s| s.trim().to_string()).collect()
                },
                tamper_scripts: if req.tamper_scripts.is_empty() {
                    vec![]
                } else {
                    req.tamper_scripts.split(',').map(|s| s.trim().to_string()).collect()
                },
                priority: req.priority,
                payload_file: if req.payload_file.is_empty() {
                    None
                } else {
                    Some(req.payload_file)
                },
            };
            
            match self.submit_job(config).await {
                Ok((job_id, queue_pos)) => {
                    Ok(Response::new(SubmitJobResponse {
                        job_id,
                        accepted: true,
                        error: String::new(),
                        queue_position: queue_pos,
                    }))
                }
                Err(e) => {
                    Ok(Response::new(SubmitJobResponse {
                        job_id: String::new(),
                        accepted: false,
                        error: e.to_string(),
                        queue_position: 0,
                    }))
                }
            }
        }
        
        async fn get_status(
            &self,
            request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            let job_id = request.into_inner().job_id;
            
            match self.get_job_status(&job_id).await {
                Some(status) => {
                    Ok(Response::new(GetStatusResponse {
                        job_id: status.job_id,
                        status: status.status as i32,
                        progress_percent: status.progress_percent,
                        findings_count: status.findings_count,
                        current_target: status.current_target,
                        payloads_tested: status.payloads_tested,
                        total_payloads: status.total_payloads,
                        error: status.error.unwrap_or_default(),
                        started_at: status.started_at.unwrap_or_default(),
                        completed_at: status.completed_at.unwrap_or_default(),
                    }))
                }
                None => {
                    Err(Status::not_found(format!("Job not found: {}", job_id)))
                }
            }
        }
        
        async fn stop_job(
            &self,
            request: Request<StopJobRequest>,
        ) -> Result<Response<StopJobResponse>, Status> {
            let req = request.into_inner();
            
            match self.stop_job(&req.job_id, req.force).await {
                Ok(final_status) => {
                    Ok(Response::new(StopJobResponse {
                        success: true,
                        final_status: final_status as i32,
                        error: String::new(),
                    }))
                }
                Err(e) => {
                    Ok(Response::new(StopJobResponse {
                        success: false,
                        final_status: 0,
                        error: e.to_string(),
                    }))
                }
            }
        }
        
        type StreamFindingsStream = tokio_stream::wrappers::ReceiverStream<Result<Finding, Status>>;
        
        async fn stream_findings(
            &self,
            request: Request<StreamFindingsRequest>,
        ) -> Result<Response<Self::StreamFindingsStream>, Status> {
            let req = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(100);
            
            // TODO: Implement finding streaming from the job
            // This would subscribe to the job's finding stream
            
            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
        }
        
        async fn list_jobs(
            &self,
            request: Request<ListJobsRequest>,
        ) -> Result<Response<ListJobsResponse>, Status> {
            let req = request.into_inner();
            
            let status_filter = if req.status_filter == 0 {
                None
            } else {
                Some(match req.status_filter {
                    1 => JobStatus::Pending,
                    2 => JobStatus::Running,
                    3 => JobStatus::Completed,
                    4 => JobStatus::Failed,
                    5 => JobStatus::Cancelled,
                    6 => JobStatus::Paused,
                    _ => JobStatus::Unknown,
                })
            };
            
            let jobs = self.list_jobs(
                status_filter,
                req.limit as usize,
                req.offset as usize,
            ).await;
            
            let job_summaries: Vec<proto::JobSummary> = jobs.into_iter().map(|j| {
                proto::JobSummary {
                    job_id: j.job_id,
                    target_url: String::new(), // Would need to fetch from job config
                    status: j.status as i32,
                    progress_percent: j.progress_percent,
                    findings_count: j.findings_count,
                    created_at: String::new(), // Would need to fetch from job
                }
            }).collect();
            
            Ok(Response::new(ListJobsResponse {
                jobs: job_summaries,
                total_count: job_summaries.len() as i32,
            }))
        }
        
        async fn health_check(
            &self,
            _request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, Status> {
            let health = self.health_check().await;
            
            Ok(Response::new(HealthCheckResponse {
                healthy: health.healthy,
                version: health.version,
                active_jobs: health.active_jobs,
                queue_size: health.queue_size,
                uptime_seconds: health.uptime_seconds,
            }))
        }
    }
    
    impl ScannerDaemon {
        /// Start the gRPC server
        pub async fn serve_grpc(&self) -> Result<()> {
            use tonic::transport::Server;
            use crate::daemon::proto::scanner_service_server::ScannerServiceServer;
            
            let addr = self.address.parse()
                .context("Invalid server address")?;
            
            info!("Starting gRPC Scanner Daemon on {}", self.address);
            
            Server::builder()
                .add_service(ScannerServiceServer::new(self.clone()))
                .serve(addr)
                .await
                .context("gRPC server failed")?;
            
            Ok(())
        }
    }
    
    impl Clone for ScannerDaemon {
        fn clone(&self) -> Self {
            Self {
                job_manager: self.job_manager.clone(),
                start_time: self.start_time,
                version: self.version.clone(),
                address: self.address.clone(),
                shutdown_tx: None, // Don't clone shutdown channel
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_daemon_creation() {
        let daemon = ScannerDaemon::new(5);
        
        assert_eq!(daemon.version(), env!("CARGO_PKG_VERSION"));
        assert!(daemon.uptime_seconds() < 1);
    }
    
    #[tokio::test]
    async fn test_submit_and_get_job() {
        let daemon = ScannerDaemon::new(5);
        
        let config = JobConfig {
            url: "http://test.com".to_string(),
            ..Default::default()
        };
        
        let (job_id, _) = daemon.submit_job(config).await.unwrap();
        
        let status = daemon.get_job_status(&job_id).await.unwrap();
        assert_eq!(status.job_id, job_id);
    }
    
    #[tokio::test]
    async fn test_health_check() {
        let daemon = ScannerDaemon::new(5);
        
        let health = daemon.health_check().await;
        
        assert!(health.healthy);
        assert_eq!(health.active_jobs, 0);
        assert_eq!(health.queue_size, 0);
    }
}
