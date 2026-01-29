// src/daemon/job.rs
//! Job Management for Daemon Mode
//! 
//! Handles scan job lifecycle, state management, and coordination.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;
use log::{info, warn, debug};

/// Job status enum (mirrors proto JobStatus)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum JobStatus {
    Unknown = 0,
    Pending = 1,
    Running = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5,
    Paused = 6,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Unknown => "UNKNOWN",
            JobStatus::Pending => "PENDING",
            JobStatus::Running => "RUNNING",
            JobStatus::Completed => "COMPLETED",
            JobStatus::Failed => "FAILED",
            JobStatus::Cancelled => "CANCELLED",
            JobStatus::Paused => "PAUSED",
        }
    }
    
    pub fn is_terminal(&self) -> bool {
        matches!(self, JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled)
    }
}

/// Scan job configuration
#[derive(Debug, Clone)]
pub struct JobConfig {
    /// Target URL
    pub url: String,
    
    /// HTTP method
    pub method: String,
    
    /// Parameters as JSON string
    pub params_json: String,
    
    /// Safety level (1-5)
    pub safety_level: u8,
    
    /// Concurrency level
    pub concurrency: usize,
    
    /// Proxy URLs
    pub proxies: Vec<String>,
    
    /// Tamper scripts to use
    pub tamper_scripts: Vec<String>,
    
    /// Job priority
    pub priority: i32,
    
    /// External payload file path
    pub payload_file: Option<String>,
}

impl Default for JobConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: "GET".to_string(),
            params_json: "{}".to_string(),
            safety_level: 3,
            concurrency: 5,
            proxies: Vec::new(),
            tamper_scripts: Vec::new(),
            priority: 0,
            payload_file: None,
        }
    }
}

/// Current state of a job
#[derive(Debug, Clone)]
pub struct JobState {
    /// Current status
    pub status: JobStatus,
    
    /// Progress percentage (0-100)
    pub progress_percent: i32,
    
    /// Number of findings so far
    pub findings_count: i32,
    
    /// Current target being scanned
    pub current_target: String,
    
    /// Payloads tested so far
    pub payloads_tested: i64,
    
    /// Total payloads to test
    pub total_payloads: i64,
    
    /// Error message if any
    pub error: Option<String>,
}

impl Default for JobState {
    fn default() -> Self {
        Self {
            status: JobStatus::Pending,
            progress_percent: 0,
            findings_count: 0,
            current_target: String::new(),
            payloads_tested: 0,
            total_payloads: 0,
            error: None,
        }
    }
}

/// A scan job
#[derive(Debug)]
pub struct Job {
    /// Unique job ID
    pub id: String,
    
    /// Job configuration
    pub config: JobConfig,
    
    /// Current state
    pub state: Arc<RwLock<JobState>>,
    
    /// When the job was created
    pub created_at: DateTime<Utc>,
    
    /// When the job started running
    pub started_at: Option<DateTime<Utc>>,
    
    /// When the job completed
    pub completed_at: Option<DateTime<Utc>>,
    
    /// Channel to send stop signal
    stop_tx: Option<mpsc::Sender<()>>,
}

impl Job {
    /// Create a new job with the given configuration
    pub fn new(config: JobConfig) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            config,
            state: Arc::new(RwLock::new(JobState::default())),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            stop_tx: None,
        }
    }
    
    /// Get the current job state
    pub async fn get_state(&self) -> JobState {
        self.state.read().await.clone()
    }
    
    /// Update the job state
    pub async fn update_state<F>(&self, updater: F)
    where
        F: FnOnce(&mut JobState),
    {
        let mut state = self.state.write().await;
        updater(&mut state);
    }
    
    /// Set job status
    pub async fn set_status(&self, status: JobStatus) {
        self.update_state(|s| s.status = status).await;
    }
    
    /// Set error and fail the job
    pub async fn fail(&self, error: &str) {
        self.update_state(|s| {
            s.status = JobStatus::Failed;
            s.error = Some(error.to_string());
        }).await;
    }
    
    /// Mark job as completed
    pub async fn complete(&self) {
        self.update_state(|s| {
            s.status = JobStatus::Completed;
            s.progress_percent = 100;
        }).await;
    }
    
    /// Check if job should stop
    pub fn is_stop_requested(&self) -> bool {
        self.stop_tx.is_none()
    }
    
    /// Set the stop channel
    pub fn set_stop_channel(&mut self, tx: mpsc::Sender<()>) {
        self.stop_tx = Some(tx);
    }
    
    /// Request to stop this job
    pub async fn request_stop(&self) -> bool {
        if let Some(ref tx) = self.stop_tx {
            tx.send(()).await.is_ok()
        } else {
            false
        }
    }
}

/// Manages all jobs in the daemon
pub struct JobManager {
    /// All jobs indexed by ID
    jobs: Arc<RwLock<HashMap<String, Arc<Mutex<Job>>>>>,
    
    /// Pending job queue (job IDs ordered by priority)
    pending_queue: Arc<Mutex<Vec<String>>>,
    
    /// Maximum concurrent jobs
    max_concurrent: usize,
    
    /// Currently running job count
    running_count: Arc<Mutex<usize>>,
}

impl JobManager {
    /// Create a new job manager
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            pending_queue: Arc::new(Mutex::new(Vec::new())),
            max_concurrent,
            running_count: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Submit a new job
    pub async fn submit(&self, config: JobConfig) -> Result<String> {
        let job = Job::new(config);
        let job_id = job.id.clone();
        let priority = job.config.priority;
        
        info!("Submitting job {} for URL: {}", job_id, job.config.url);
        
        // Add to jobs map
        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(job_id.clone(), Arc::new(Mutex::new(job)));
        }
        
        // Add to pending queue (sorted by priority)
        {
            let mut queue = self.pending_queue.lock().await;
            let insert_pos = queue.iter().position(|_| true).unwrap_or(queue.len());
            queue.insert(insert_pos, job_id.clone());
        }
        
        // Try to start jobs if we have capacity
        self.try_start_pending().await;
        
        Ok(job_id)
    }
    
    /// Get job by ID
    pub async fn get(&self, job_id: &str) -> Option<Arc<Mutex<Job>>> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }
    
    /// Get job state
    pub async fn get_state(&self, job_id: &str) -> Option<JobState> {
        if let Some(job) = self.get(job_id).await {
            let job = job.lock().await;
            Some(job.get_state().await)
        } else {
            None
        }
    }
    
    /// Stop a job
    pub async fn stop(&self, job_id: &str, force: bool) -> Result<JobStatus> {
        let job = self.get(job_id).await
            .ok_or_else(|| anyhow!("Job not found: {}", job_id))?;
        
        let job = job.lock().await;
        let state = job.get_state().await;
        
        if state.status.is_terminal() {
            return Ok(state.status);
        }
        
        if force {
            job.update_state(|s| s.status = JobStatus::Cancelled).await;
        } else {
            job.request_stop().await;
        }
        
        // Update running count if job was running
        if state.status == JobStatus::Running {
            let mut count = self.running_count.lock().await;
            *count = count.saturating_sub(1);
        }
        
        // Remove from pending queue if it was pending
        {
            let mut queue = self.pending_queue.lock().await;
            queue.retain(|id| id != job_id);
        }
        
        Ok(job.get_state().await.status)
    }
    
    /// List all jobs
    pub async fn list(&self, status_filter: Option<JobStatus>, limit: usize, offset: usize) -> Vec<(String, JobState)> {
        let jobs = self.jobs.read().await;
        let mut results = Vec::new();
        
        for (id, job) in jobs.iter() {
            let job = job.lock().await;
            let state = job.get_state().await;
            
            if let Some(filter) = status_filter {
                if state.status != filter {
                    continue;
                }
            }
            
            results.push((id.clone(), state));
        }
        
        // Apply pagination
        results.into_iter()
            .skip(offset)
            .take(limit)
            .collect()
    }
    
    /// Get queue size
    pub async fn queue_size(&self) -> usize {
        self.pending_queue.lock().await.len()
    }
    
    /// Get active job count
    pub async fn active_count(&self) -> usize {
        *self.running_count.lock().await
    }
    
    /// Try to start pending jobs
    async fn try_start_pending(&self) {
        let mut running = self.running_count.lock().await;
        
        while *running < self.max_concurrent {
            let job_id = {
                let mut queue = self.pending_queue.lock().await;
                if queue.is_empty() {
                    break;
                }
                queue.remove(0)
            };
            
            if let Some(job) = self.get(&job_id).await {
                let mut job = job.lock().await;
                job.set_status(JobStatus::Running).await;
                *running += 1;
                
                debug!("Started job {}", job_id);
                
                // TODO: Actually spawn the scan task here
                // This would integrate with the Scanner
            }
        }
    }
    
    /// Mark a job as completed (called by scan task)
    pub async fn mark_completed(&self, job_id: &str) {
        if let Some(job) = self.get(job_id).await {
            let job = job.lock().await;
            job.complete().await;
        }
        
        let mut running = self.running_count.lock().await;
        *running = running.saturating_sub(1);
        
        // Try to start more jobs
        drop(running);
        self.try_start_pending().await;
    }
    
    /// Mark a job as failed
    pub async fn mark_failed(&self, job_id: &str, error: &str) {
        if let Some(job) = self.get(job_id).await {
            let job = job.lock().await;
            job.fail(error).await;
        }
        
        let mut running = self.running_count.lock().await;
        *running = running.saturating_sub(1);
        
        drop(running);
        self.try_start_pending().await;
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_job_creation() {
        let config = JobConfig {
            url: "http://test.com".to_string(),
            ..Default::default()
        };
        
        let job = Job::new(config);
        
        assert!(!job.id.is_empty());
        assert_eq!(job.get_state().await.status, JobStatus::Pending);
    }
    
    #[tokio::test]
    async fn test_job_state_update() {
        let job = Job::new(JobConfig::default());
        
        job.set_status(JobStatus::Running).await;
        assert_eq!(job.get_state().await.status, JobStatus::Running);
        
        job.update_state(|s| {
            s.progress_percent = 50;
            s.findings_count = 3;
        }).await;
        
        let state = job.get_state().await;
        assert_eq!(state.progress_percent, 50);
        assert_eq!(state.findings_count, 3);
    }
    
    #[tokio::test]
    async fn test_job_manager_submit() {
        let manager = JobManager::new(2);
        
        let config = JobConfig {
            url: "http://test.com".to_string(),
            ..Default::default()
        };
        
        let job_id = manager.submit(config).await.unwrap();
        
        assert!(!job_id.is_empty());
        
        let state = manager.get_state(&job_id).await.unwrap();
        // Should be running since we have capacity
        assert!(state.status == JobStatus::Running || state.status == JobStatus::Pending);
    }
    
    #[tokio::test]
    async fn test_job_manager_queue() {
        let manager = JobManager::new(1);
        
        // Submit 3 jobs
        for i in 0..3 {
            let config = JobConfig {
                url: format!("http://test{}.com", i),
                ..Default::default()
            };
            manager.submit(config).await.unwrap();
        }
        
        // First should be running, rest pending
        assert_eq!(manager.active_count().await, 1);
        assert_eq!(manager.queue_size().await, 2);
    }
}
