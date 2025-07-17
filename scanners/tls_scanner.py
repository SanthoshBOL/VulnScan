import os
import subprocess
import datetime
import shutil
import logging
from PIL import Image, ImageDraw, ImageFont
from concurrent.futures import ThreadPoolExecutor, as_completed
from zoneinfo import ZoneInfo  # Python 3.9+

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

WEAK_TLS_INDICATORS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "EXP", "LOW", "MEDIUM", "CBC", "RC4", "3DES"]
COVER_IMAGE_PATH = "assets/TLS_Cover.jpg"
FONT_BOLD = "assets/Times-Bold.ttf"
FONT_REGULAR = "assets/Times-Roman.ttf"

def check_dependencies():
    if shutil.which("nmap") is None:
        logging.error("Nmap not found! Please install it.")
        exit(1)

def load_fonts():
    try:
        return (
            ImageFont.truetype(FONT_BOLD, 50),
            ImageFont.truetype(FONT_REGULAR, 35),
            ImageFont.truetype(FONT_REGULAR, 22),
        )
    except:
        logging.warning("Font loading failed, using default fonts.")
        return ImageFont.load_default(), ImageFont.load_default(), ImageFont.load_default()

def scan_target(target: str) -> tuple[str, str]:
    try:
        result = subprocess.run([
            "nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", "443", target
        ], capture_output=True, text=True, timeout=60)
        return target, result.stdout or "⚠️ No output or scan failed."
    except subprocess.TimeoutExpired:
        return target, "⚠️ Scan timed out."
    except Exception as e:
        return target, f"⚠️ Error scanning {target}: {e}"

def run_ssl_scan(targets_file: str, output_pdf: str):
    check_dependencies()

    if not os.path.exists(targets_file):
        logging.error(f"Target file not found: {targets_file}")
        return

    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]

    if not targets:
        logging.error("No targets found in file.")
        return

    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = f"TLS-SEC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

    scan_results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(scan_target, t): t for t in targets}
        for future in as_completed(future_to_target):
            target, result = future.result()
            logging.info(f"Scanned {target}")
            scan_results[target] = result

    os.makedirs(os.path.dirname(output_pdf), exist_ok=True)
    create_pdf(scan_results, output_pdf, scan_date, report_id)
    logging.info(f"Report saved at: {output_pdf}")

def create_pdf(scan_results: dict, output_pdf: str, scan_date: str, report_id: str):
    images = []
    strong_targets, weak_targets = [], {}

    if os.path.exists(COVER_IMAGE_PATH):
        cover_img = Image.open(COVER_IMAGE_PATH).convert("RGB").resize((1000, 1454))
        images.append(cover_img)
    else:
        logging.warning("Cover image not found. Skipping.")

    title_font, header_font, body_font = load_fonts()

    for target, output in scan_results.items():
        if any(w in output for w in WEAK_TLS_INDICATORS):
            weak_targets[target] = [l for l in output.splitlines() if any(w in l for w in WEAK_TLS_INDICATORS)]
        else:
            strong_targets.append(target)

    cover = Image.new("RGB", (1000, 1400), "white")
    draw = ImageDraw.Draw(cover)
    draw.rectangle([(0, 0), (1000, 200)], fill="black")
    draw.text((250, 80), "TLS/SSL Scan Report", font=title_font, fill="red")
    draw.rectangle([(0, 1250), (1000, 1400)], fill="black")
    draw.text((300, 1300), "Confidential Security Report", font=header_font, fill="red")
    draw.text((100, 300), "Prepared by: Security Team", font=header_font, fill="black")
    draw.text((100, 350), f"Date: {scan_date}", font=header_font, fill="black")
    draw.text((100, 400), f"Report ID: {report_id}", font=header_font, fill="black")
    draw.text((100, 500), "Scope: External TLS/SSL Security Assessment", font=header_font, fill="black")
    draw.text((100, 550), "Method: Automated using Nmap", font=header_font, fill="black")
    draw.text((100, 700), "Security Findings Summary:", font=header_font, fill="red")
    draw.text((100, 750), f"• Targets Scanned: {len(scan_results)}", font=body_font, fill="black")
    draw.text((100, 800), f"• Strong Ciphers: {len(strong_targets)}", font=body_font, fill="green")
    draw.text((100, 850), f"• Weak Ciphers: {len(weak_targets)}", font=body_font, fill="red")
    draw.text((100, 900), f"• High-Risk: {sum(1 for t in weak_targets if any(w in ''.join(weak_targets[t]) for w in ['TLS 1.0', 'RC4']))}", font=body_font, fill="red")
    draw.text((100, 950), f"• Medium-Risk: {sum(1 for t in weak_targets if 'CBC' in ''.join(weak_targets[t]))}", font=body_font, fill="orange")
    images.append(cover)

    summary = Image.new("RGB", (1000, 1400), "white")
    draw = ImageDraw.Draw(summary)
    y = 150
    draw.text((100, y), "Strong Cipher Configurations", font=header_font, fill="green")
    y += 50
    for t in strong_targets:
        draw.text((120, y), f"• {t}", font=body_font, fill="black")
        y += 30
    y += 40
    draw.text((100, y), "Weak Cipher Configurations", font=header_font, fill="red")
    y += 50
    for t, issues in weak_targets.items():
        draw.text((120, y), f"{t}:", font=body_font, fill="black")
        y += 30
        for issue in issues:
            draw.text((140, y), f"⚠️ {issue.strip()}", font=body_font, fill="red")
            y += 25
        y += 10
    images.append(summary)

    for target, output in scan_results.items():
        page = Image.new("RGB", (1000, 1400), "white")
        draw = ImageDraw.Draw(page)
        draw.text((100, 80), f"Scan Result for {target}", font=header_font, fill="black")
        draw.rectangle([(50, 200), (950, 1350)], outline="black", width=3)
        y = 220
        for line in output.splitlines():
            if y > 1300:
                break
            color = "red" if any(w in line for w in WEAK_TLS_INDICATORS) else "black"
            draw.text((70, y), line.strip(), font=body_font, fill=color)
            y += 25
        images.append(page)

    images[0].save(output_pdf, save_all=True, append_images=images[1:])


if __name__ == "__main__":
    targets_file = "data/ssl_targets.txt"

    now_ist = datetime.datetime.now(ZoneInfo("Asia/Kolkata"))
    time_str = now_ist.strftime("%I-%M %p")  # e.g., 03-21 PM
    date_str = now_ist.strftime("%d-%m-%Y")
    report_name = f"{time_str}_IST_{date_str}_tls_scan_report.pdf"
    output_pdf = os.path.join("reports/ssl_reports", report_name)

    run_ssl_scan(targets_file, output_pdf)