import datetime
import os
import argparse
from zoneinfo import ZoneInfo
from scanners.tls_scanner import run_ssl_scan
from scanners.public_api_scan import run_public_api_scan

def get_timestamp():
    now_ist = datetime.datetime.now(ZoneInfo("Asia/Kolkata"))
    time_str = now_ist.strftime("%I-%M %p")
    date_str = now_ist.strftime("%d-%m-%Y")
    return time_str, date_str

def run_ssl():
    time_str, date_str = get_timestamp()
    ssl_targets_file = "data/ssl_targets.txt"
    tls_report_name = f"{time_str}_IST_{date_str}_tls_scan_report.pdf"
    tls_output_path = os.path.join("reports/ssl_reports", tls_report_name)

    print("[*] Running TLS/SSL scan...")
    run_ssl_scan(ssl_targets_file, tls_output_path)

def run_public_api():
    time_str, date_str = get_timestamp()
    public_api_targets = "data/public_apis.txt"
    public_api_report = f"{time_str}_IST_{date_str}_public_api_scan_report.pdf"
    public_api_output = os.path.join("reports/public_api_scan_reports", public_api_report)

    print("[*] Running Public API Access scan...")
    run_public_api_scan(public_api_targets, public_api_output)

def main():
    parser = argparse.ArgumentParser(description="VulnScan - Security Tools CLI")
    parser.add_argument(
        "scan",
        choices=["sslscan", "publicapiscan", "all"],
        help="Type of scan to run"
    )

    args = parser.parse_args()

    if args.scan == "sslscan":
        run_ssl()
    elif args.scan == "publicapiscan":
        run_public_api()
    elif args.scan == "all":
        run_ssl()
        run_public_api()

if __name__ == "__main__":
    main()
