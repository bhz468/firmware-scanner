import argparse
import os
import hashlib
import sqlite3
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.extractor import extract_firmware
from scanner.credential_hunter import hunt_credentials
from scanner.cve_matcher import extract_versions, query_nvd
from scanner.binary_hardening import check_all_binaries
from scanner.risk_scorer import score_findings, summarize
from scanner.report import save_json, save_html, print_summary

DB_PATH = "/tmp/scanner_cache.db"

def get_firmware_hash(firmware_path: str) -> str:
    h = hashlib.md5()
    with open(firmware_path, "rb") as f:
        h.update(f.read(1024 * 1024))  # Hash des premiers 1MB
    return h.hexdigest()

def cache_get(firmware_hash: str) -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT findings FROM scans WHERE hash=?", (firmware_hash,)
        ).fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None

def cache_set(firmware_hash: str, findings: list):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (hash TEXT PRIMARY KEY, findings TEXT)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?, ?)",
            (firmware_hash, json.dumps(findings))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Firmware Vulnerability Scanner")
    parser.add_argument("firmware", help="Path to firmware binary")
    parser.add_argument("--output", default="reports/report.json")
    parser.add_argument("--no-cache", action="store_true", help="Force rescan")
    args = parser.parse_args()

    print(f"[*] Scanning {args.firmware}...")

    # Vérifie le cache
    fw_hash = get_firmware_hash(args.firmware)
    if not args.no_cache:
        cached = cache_get(fw_hash)
        if cached is not None:
            print(f"[✓] Cache hit — résultats instantanés !")
            ranked  = score_findings(cached)
            summary = summarize(ranked)
            html_output = args.output.replace(".json", ".html")
            save_json(ranked, args.output)
            save_html(ranked, summary, args.firmware, html_output)
            print_summary(ranked, summary)
            return

    print("[*] Extracting firmware...")
    extracted = extract_firmware(args.firmware, "/tmp/fw_extracted")

    rootfs = "/tmp/fw_extracted"
    for root, dirs, _ in os.walk("/tmp/fw_extracted"):
        if "squashfs-root" in dirs:
            rootfs = os.path.join(root, "squashfs-root")
            break
    print(f"[*] Rootfs found at: {rootfs}")

    findings = []

    print("[*] Running analysis in parallel...")
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_creds     = executor.submit(hunt_credentials, rootfs)
        future_hardening = executor.submit(check_all_binaries, rootfs)
        future_versions  = executor.submit(extract_versions, rootfs)

        creds = future_creds.result()
        findings += creds
        print(f"    ✓ Credentials: {len(creds)} findings")

        hardening = future_hardening.result()
        findings += hardening
        print(f"    ✓ Hardening: {len(hardening)} findings")

        versions = future_versions.result()

    print("[*] Matching CVEs in parallel...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(query_nvd, comp["component"], comp["version"]): comp
            for comp in versions[:5]
        }
        for future in as_completed(futures):
            try:
                cves = future.result()
                findings += cves
                if cves:
                    print(f"    ✓ {len(cves)} CVEs for {futures[future]['component']}")
            except Exception:
                pass

    # Sauvegarde dans le cache
    cache_set(fw_hash, findings)
    print("[✓] Résultats mis en cache pour la prochaine fois")

    print("[*] Scoring findings...")
    ranked  = score_findings(findings)
    summary = summarize(ranked)

    html_output = args.output.replace(".json", ".html")
    save_json(ranked, args.output)
    save_html(ranked, summary, args.firmware, html_output)
    print_summary(ranked, summary)

if __name__ == "__main__":
    main()
    