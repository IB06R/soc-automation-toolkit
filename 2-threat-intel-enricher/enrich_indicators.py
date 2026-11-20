import argparse
import csv
import ipaddress
import os
import re
import sys
import time
from datetime import datetime
import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_unique_ips(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    extracted = []
    with open(filepath, "r", encoding="utf-8-sig") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for match in IPV4_REGEX.findall(stripped):
                try:
                    ipaddress.ip_address(match)
                    extracted.append(match)
                except ValueError:
                    continue

    # Deduplicate while preserving order
    return list(dict.fromkeys(extracted))


def check_ip(ip: str, api_key: str) -> dict:
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
        return {
            "ip": ip,
            "status": "SKIPPED_INTERNAL",
            "score": 0,
            "country": "LOCAL",
            "isp": "Private/Internal Network",
            "total_reports": 0,
        }

    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(
            API_URL, headers=headers, params=params, timeout=10
        )
        if response.status_code == 429:
            return {"ip": ip, "status": "RATE_LIMITED", "score": -1}
        if response.status_code == 401:
            return {"ip": ip, "status": "INVALID_API_KEY", "score": -1}
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip": ip,
            "status": "OK",
            "score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0),
        }
    except requests.RequestException as exc:
        return {"ip": ip, "status": f"ERROR: {exc}", "score": -1}


def main():
    parser = argparse.ArgumentParser(
        description="Extract, deduplicate, and enrich IPv4 indicators via AbuseIPDB."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="sample_iocs.txt",
        help="Path to text, CSV, or raw log file containing IP addresses",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=f"enriched_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV path (defaults to timestamped filename)",
    )
    args = parser.parse_args()

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print(
            "[!] Missing ABUSEIPDB_API_KEY environment variable.",
            file=sys.stderr,
        )
        print(
            "    Set it in PowerShell: $env:ABUSEIPDB_API_KEY='your_key_here'",
            file=sys.stderr,
        )
        sys.exit(1)

    ips = extract_unique_ips(args.input_file)
    print(f"[*] Found {len(ips)} unique valid IP(s) in '{args.input_file}'...\n")

    results = []
    for ip in ips:
        res = check_ip(ip, api_key)
        results.append(res)

        if res["status"] == "SKIPPED_INTERNAL":
            verdict = "INTERNAL"
        elif res["status"] != "OK":
            verdict = "ERROR"
        elif res["score"] >= 50:
            verdict = "MALICIOUS"
        elif res["score"] > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        print(
            f"[{verdict:<10}] {ip:<16} | Score: {res['score']:>3}% | "
            f"Reports: {res.get('total_reports', 0):<4} | ISP: {res.get('isp', 'N/A')}"
        )

        # Only sleep if an external API call was actually made
        if res["status"] != "SKIPPED_INTERNAL":
            time.sleep(1.1)

    with open(args.output, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "ip",
                "status",
                "score",
                "country",
                "isp",
                "total_reports",
            ],
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Saved full threat-intel report to {args.output}")


if __name__ == "__main__":
    main()
