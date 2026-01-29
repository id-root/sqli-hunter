use statistical::standard_deviation;
use rquest::Client;
use std::time::Duration;
use log::info;
use crate::models::Target;

pub struct Calibration;

impl Calibration {
    pub async fn calibrate(client: &Client, target: &Target) -> Result<f64, anyhow::Error> {
        info!("Starting Calibration (Phase 1) for {}...", target.url);
        
        let mut latencies = Vec::new();
        // Send 20 requests
        for _ in 0..20 {
            let start = std::time::Instant::now();
            let _resp = client.request(target.method.parse().unwrap(), &target.url)
                // Add params? Ideally yes to match attack surface
                .send().await?;
            let duration = start.elapsed().as_millis() as f64;
            latencies.push(duration);
            tokio::time::sleep(Duration::from_millis(50)).await; // Slight delay
        }

        let mean = statistical::mean(&latencies);
        let std_dev = standard_deviation(&latencies, Some(mean));
        
        info!("Calibration complete. Mean Latency: {:.2}ms, StdDev: {:.2}ms", mean, std_dev);
        
        // Stability Score: lower std_dev is better.
        // Return std_dev as score.
        Ok(std_dev)
    }
}
