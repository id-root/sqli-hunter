use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "RustSQLi-Phantom-Ops")]
#[command(author = "Jules")]
#[command(version = "5.0.0")]
#[command(about = "A high-performance, asynchronous SQL injection fuzzer/scanner.", long_about = None)]
pub struct Args {
    /// Add a single target URL to the scan queue.
    #[arg(short, long)]
    pub url: Option<String>,

    /// HTTP Method for the target (GET/POST).
    #[arg(short, long, default_value = "GET")]
    pub method: String,

    /// JSON string of parameters to fuzz (e.g., '{"id":"1"}').
    #[arg(short, long)]
    pub params: Option<String>,

    /// Path to a text file containing proxy URLs (one per line).
    #[arg(long)]
    pub proxy_file: Option<String>,

    /// Number of concurrent scanning threads.
    #[arg(short, long, default_value_t = 5)]
    pub concurrency: usize,

    /// Path to external payload file (SecLists).
    #[arg(long)]
    pub payloads: Option<String>,

    /// Enable specific Tamper scripts (comma-separated: Space2Comment,Between,HPP,Chunked).
    #[arg(long)]
    pub tamper: Option<String>,

    /// Enables Spider mode on the given domain URL.
    #[arg(long)]
    pub domain: Option<String>,

    /// Enables OOB injection using the provided OOB interaction domain.
    #[arg(long)]
    pub oob: Option<String>,

    /// Spider recursion depth (default: 2).
    #[arg(long, default_value_t = 2)]
    pub depth: usize,

    /// Manually pass a cookie string (e.g., "id=123; waf_token=abc")
    #[arg(long)]
    pub cookie: Option<String>,

    // --- NEW FLAGS ---
    
    /// Resume scan from database (skip adding new targets/spiders).
    #[arg(long)]
    pub resume: bool,

    /// Save findings to a specific JSON file at the end.
    #[arg(long)]
    pub output: Option<String>,
}
