<p align="center">
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Suite-Orion-blue" alt="Suite: Orion">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/version-5.0.0-black.svg" alt="Version 5.0.0">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Engine-Omniscient-blueviolet" alt="Engine: Omniscient">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Architecture-Hunter--Gatherer-red" alt="Architecture: Hunter-Gatherer">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
  </a>
</p>


# SQLi Hunter

This  is a high-performance, asynchronous SQL Injection vulnerability scanner written in Rust. It is designed for advanced discovery, evasion, and exploitation of SQL injection flaws in modern web applications.

It features a "Hunter-Gatherer" architecture when paired with its companion tool, [Spectre](https://github.com/id-root/spectre).

---

## ⚠️ Disclaimer

> **This tool is for educational purposes and authorized security testing only.**
> You must have explicit permission from the owner of the target system before scanning. The authors accept no responsibility for unauthorized use or damage caused by this tool. Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.

---

## 🔥 Key Features

* **⚡ High-Performance:** Built on the `Tokio` async runtime for massive concurrency.
* **🧠 Omniscient Detection:** Uses heuristic analysis to detect Error-Based, Boolean-Based, and Time-Based Blind injections.
* **🛡️ WAF Evasion:** Bypass Cloudflare, Akamai, and other WAFs by integrating valid session cookies.
* **🕸️ Built-in Spider:** Can crawl an entire domain to discover injection points automatically.
* **📡 Out-of-Band (OOB):** Supports DNS/HTTP interaction payloads (MySQL, PostgreSQL, Oracle, MSSQL) to detect hidden vulnerabilities.
* **💾 State Persistence:** All targets and findings are saved to a local SQLite database (`fuzzer.db`), allowing you to pause and resume scans.

---

## 🛠️ Installation

### Prerequisites

* **Rust & Cargo:** [Install Rust](https://rustup.rs/)

### Build from Source

```bash
git clone https://github.com/id-root/sqli-hunter
cd sqli-hunter
cargo build --release

```

The binary will be located at `./target/release/rust_sqli_hunter`.

---

## 🚀 Usage Guide

### 1. Basic Scan (Single URL)

Scan a specific URL with known parameters.

```bash
# Scan a specific endpoint
./rust_sqli_hunter --url "http://target.com/product.php" --params '{"id":"1"}'

```

### 2. Domain Discovery (Spider Mode)

Crawl a domain to automatically find targets and add them to the scan queue.

```bash
# Crawl up to depth 3
./rust_sqli_hunter --domain "http://target.com" --depth 3

```

### 3. WAF Bypass (The "Spectre" Workflow)

To scan protected targets (Cloudflare, Datadome, etc.), you must provide a valid session cookie. We recommend using [Spectre](https://github.com/id-root/spectre) to acquire this.

**Step 1: Get Cookie with Spectre**

```bash
# (Run this in the Spectre directory)
./spectre --url "https://protected-target.com"
# Output saved to last_cookie.txt

```

**Step 2: Scan with SQLi Hunter**
Pass the cookie string using the `--cookie` flag.

```bash
./rust_sqli_hunter \
  --url "https://protected-target.com/search" \
  --params '{"q":"test"}' \
  --cookie "cf_clearance=x7z-bypass-token-99"

```

*Pro Tip: You can automate this by reading the file:* `--cookie "$(cat last_cookie.txt)"`

### 4. Resuming a Scan

If you stopped a scan or added targets via the Spider, use `--resume` to skip the setup and immediately start processing the queue.

```bash
./rust_sqli_hunter --resume

```

### 5. Exporting Results

Save all found vulnerabilities to a JSON file.

```bash
./rust_sqli_hunter --resume --output results.json

```

---

## ⚙️ CLI Options Reference

| Flag | Description | Example |
| --- | --- | --- |
| `--url <URL>` | Target URL to scan. | `http://site.com/api` |
| `--params <JSON>` | JSON string of parameters to fuzz. | `'{"id":"1", "q":"search"}'` |
| `--method <GET/POST>` | HTTP Method (Default: GET). | `--method POST` |
| `--domain <URL>` | Enable Spider mode on this domain. | `--domain http://site.com` |
| `--depth <N>` | Recursion depth for Spider (Default: 2). | `--depth 3` |
| `--cookie <STR>` | Manually pass WAF-bypass cookies. | `--cookie "PHPSESSID=xyz"` |
| `--concurrency <N>` | Number of concurrent threads (Default: 5). | `--concurrency 20` |
| `--proxy-file <FILE>` | Path to a list of proxies (one per line). | `--proxy-file proxies.txt` |
| `--payloads <FILE>` | Path to custom payload file (SecLists). | `--payloads list.txt` |
| `--oob <DOMAIN>` | Enable OOB detection using this interaction domain. | `--oob collaborator.com` |
| `--resume` | Resume scan from local DB (skip target add). | `--resume` |
| `--output <FILE>` | Save findings to a JSON file. | `--output report.json` |

---

## 🤝 Integration with Spectre

This tool is designed to work seamlessly with **Spectre**, a specialized "Gatherer" tool for bypassing advanced WAF challenges.

* **Spectre** handles the browser fingerprinting and challenge solving (JS/Captcha).
* **SQLi Hunter** uses the session established by Spectre to deliver payloads without getting blocked.

**Project Link:** [github.com/id-root/spectre](https://github.com/id-root/spectre)

### Recommended Workflow

1. **Gather:** Run `spectre` against the target to identify WAF type and extract the session cookie.
2. **Hunt:** Run `sqli-hunter` with the extracted cookie to fuzz the application logic.

---

## 🏗️ Architecture

* **Context Engine:** Analyzes input (Integer vs. String vs. JSON) to tailor payloads.
* **Heuristic Analyzer:** regex-based detection for generic and specific DB errors.
* **Database:** Uses SQLite (`fuzzer.db`) for robust state management.
* **Tamper Pipeline:** (Optional) Modifies payloads (e.g., `Space2Comment`) to evade filters.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
