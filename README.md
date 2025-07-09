🔐 VulnScan – Internal Security Scanning Framework
VulnScan is an internal-use, modular security scanning framework. It currently supports automated TLS/SSL cipher analysis, with plans to expand into certificate validation, HTTP header checks, subdomain enumeration, and more.

Integrated with GitHub Actions, it auto-generates detailed PDF reports from daily scans at 3:00 AM IST, helping your team monitor and improve security posture continuously.

🚨 VulnScan is a private tool developed strictly for internal use within the organization.

✅ Current Capabilities
🔒 TLS/SSL Cipher Suite Scanner using Nmap (ssl-enum-ciphers)

📊 Risk-based classification (Strong, Weak, High-Risk, Medium-Risk)

🧾 Well-structured PDF reports with cover, summary, and findings

💥 Parallel scanning for faster execution

📧 Email automation (latest report only)

🗃️ Artifact archival of all generated reports

🕒 Runs daily at 3:00 AM IST via GitHub Actions