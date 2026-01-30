<p align="center">
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Suite-Orion-blue" alt="Suite: Orion">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/release-Titan v6.0-fb8b24" alt="Release: Titan (v6.0)">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Architecture-Hunter--Gatherer-red" alt="Architecture: Hunter-Gatherer">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
  </a>
</p>


# SQLi Hunter: Titan Edition

**RustSQLi-Hunter Titan** is an asynchronous SQL Injection vulnerability scanner. It combines high-performance concurrency with deep structural analysis and browser-based automation to detect complex vulnerabilities in modern applications.

---

## ⚠️ Disclaimer

> **This tool is for educational purposes and authorized security testing only.**
> You must have explicit permission from the owner of the target system before scanning. The authors accept no responsibility for unauthorized use or damage caused by this tool. Usage of this tool for attacking targets without prior mutual consent is illegal.

---

## 🔥 Titan Release Features

*   **🔒 Authentication Macros:** Automate complex login flows (MFA, SSO, Captcha) using headless browser scripts.
*   **📊 TUI Dashboard:** Real-time terminal dashboard with live traffic, finding logs, and progress statistics.
*   **🧠 Structural Analysis:** DOM-based differential analysis to detect subtle injection flaws (blind/error-based).
*   **📡 Distributed Scanning:** Run as a gRPC daemon to offload scanning jobs or integrate with CI/CD pipelines.
*   **🛡️ Safety Throttling:** Smart rate-limiting and payload filtering based on destructiveness levels (1-5).
*   **📑 Professional Reporting:** Generate PDF executive reports or CI/CD-friendly SARIF/JUnit output.

---

## 🛠️ Installation

### Prerequisites
*   **Rust & Cargo:** [Install Rust](https://rustup.rs/)
*   **Google Chrome / Chromium:** Required for authentication macros.

### Build from Source

```bash
git clone https://github.com/id-root/sqli-hunter
cd sqli-hunter
cargo build --release
```

Binary location: `./target/release/rust_sqli_hunter`

---

## 🚀 Usage Guide

### 1. Basic Scan
Scan a single URL with specific parameters.

```bash
./rust_sqli_hunter --url "http://target.com/product.php" --params '{"id":"1"}'
```

### 2. Authenticated Scan (New!)
Use a YAML macro to handle login automatically.

```bash
./rust_sqli_hunter \
  --url "http://internal-app.local/search" \
  --params '{"q":"test"}' \
  --auth-macro macros/login_flow.yml
```

**Example Macro (`macros/login.yml`):**
```yaml
name: "Admin Login"
target_url: "http://target.com/login"
steps:
  - action: navigate
    value: "http://target.com/login"
  - action: type
    selector: "#username"
    value: "admin"
  - action: type
    selector: "#password"
    value: "secret"
  - action: click
    selector: "#login-btn"
```

### 3. TUI Dashboard
Visualize the scan progress in real-time.

```bash
./rust_sqli_hunter --url "http://target.com" --depth 2 --dashboard
```

### 4. Safety & Stealth
Control scan aggressiveness to avoid WAF detection or DB outages.

```bash
# Level 1 (Aggressive) to Level 5 (Stealth/Safe)
./rust_sqli_hunter --url "..." --safety-level 5
```

### 5. Distributed Daemon Mode
Start the scanner as a gRPC service.

```bash
# Start Server
./rust_sqli_hunter --daemon --daemon-addr "0.0.0.0:50051"

# Submit Job (using grpcurl or client)
grpcurl -d '{"url": "..."}' -plaintext localhost:50051 sqli_hunter.ScannerService/SubmitJob
```

### 6. Reporting
Generate artifacts for auditors or CI/CD systems.

```bash
# Professional PDF
./rust_sqli_hunter --resume --output-pdf report.pdf

# CI/CD Integration
./rust_sqli_hunter --resume --format sarif --output results.sarif
```

---

## ⚙️ CLI Options Reference

| Flag | Description | Example |
| --- | --- | --- |
| `--url <URL>` | Target URL to scan. | `http://site.com/api` |
| `--params <JSON>` | JSON parameters to fuzz. | `'{"id":"1"}'` |
| `--auth-macro <FILE>` | Path to auth workflow YAML. | `--auth-macro login.yml` |
| `--dashboard` | Enable TUI dashboard. | `--dashboard` |
| `--safety-level <1-5>` | Safety/Stealth level. | `--safety-level 5` |
| `--format <FMT>` | Output format (json, sarif, junit). | `--format sarif` |
| `--daemon` | Run as gRPC server. | `--daemon` |
| `--domain <URL>` | Enable crawler. | `--domain http://site.com` |
| `--depth <N>` | Crawl depth. | `--depth 3` |
| `--concurrency <N>` | Thread count. | `--concurrency 10` |

---

## 🏗️ Architecture

*   **Cyber-Brain (Analysis):** `html5ever` DOM diffing & `sqlparser` AST analysis.
*   **Suit (Integration):** `headless_chrome` automation & `serde_sarif` reporting.
*   **Muscle (Scale):** `tonic` gRPC server & `tokio` async runtime.
*   **Face (UI):** `ratatui` dashboard & `genpdf` report engine.

---

## 📜 License
MIT License.
