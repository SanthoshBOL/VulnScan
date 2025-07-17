
# 🛡️ VulnScan

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/github/license/your-org/security)

**VulnScan** is a modular, extensible security automation tool built by the **Security Team** to streamline internal security assessments across your organization's infrastructure.

---

## � Features

### 1. SSL/TLS Scan (`sslscan`)
* **Checks for:**
  - Expired or weak certificates
  - Insecure protocols and cipher suites
  - Missing security headers
* **Targets:** `data/ssl_targets.txt`
* **Reports:** PDF output in `reports/ssl_reports/`

### 2. Public API Access Scan (`publicapiscan`)
* **Detects:**
  - Unauthenticated access to internal API endpoints
  - Publicly accessible or misconfigured routes
* **Inputs:**
  - Domains: `data/gravty_domains.txt`
  - API paths: `data/public_apis.txt`
* **Reports:** PDF output in `reports/public_api_scan_reports/`

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/your-org/security.git
cd security/tools/VulnScan
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Scans

**Run a specific scan:**

```bash
python main.py sslscan
python main.py publicapiscan
```

**Run all scans:**

```bash
python main.py all
```

---

## 📁 Directory Structure

```
VulnScan/
├── main.py
├── requirements.txt
├── scanners/
│   ├── public_api_scan.py
│   └── tls_scanner.py
├── data/
│   ├── gravty_domains.txt
│   ├── public_apis.txt
│   └── ssl_targets.txt
├── reports/
│   ├── public_api_scan_reports/
│   └── ssl_reports/
└── assets/
```

---

## 📝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

---

## 📢 Disclaimer

This tool is for **internal and authorized use only**. Use responsibly and in accordance with your organization's security policies and incident response protocols.

---

## 👨‍💻 Maintainers

Security Team  
Built with ❤️ to empower teams with proactive security automation.
