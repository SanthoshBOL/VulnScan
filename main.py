from scanners.tls_scanner import run_ssl_scan
import datetime
import os
from zoneinfo import ZoneInfo

def main():
    # Define input path
    targets_file = "data/targets.txt"

    now_ist = datetime.datetime.now(ZoneInfo("Asia/Kolkata"))
    time_str = now_ist.strftime("%I-%M %p")  # e.g., 03-21 PM
    date_str = now_ist.strftime("%d-%m-%Y")
    report_name = f"{time_str}_IST_{date_str}_tls_scan_report.pdf"
    output_pdf = os.path.join("reports", report_name)

    # Run the scanner
    run_ssl_scan(targets_file, output_pdf)

if __name__ == "__main__":
    main()