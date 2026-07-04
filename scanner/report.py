import json
import os
from datetime import datetime

def save_json(findings: list, output_path: str):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[+] JSON report saved → {output_path}")

def save_html(findings: list, summary: dict, firmware_path: str, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    severity_color = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#3498db",
        "UNKNOWN":  "#95a5a6"
    }

    rows = ""
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        color = severity_color.get(sev, "#95a5a6")
        ftype = f.get("type", f.get("cve_id", "unknown"))
        detail = f.get("match", f.get("description", f.get("file", "")))[:100]
        cve_id = f.get("cve_id", "")
        cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank">{cve_id}</a>' if cve_id else "—"
        rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td>{ftype}</td>
            <td>{cve_link}</td>
            <td style="font-size:12px;color:#666">{detail}</td>
        </tr>"""

    total = len(findings)
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Firmware Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; color: #00d4ff; margin-bottom: 0.3rem; }}
  .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: #1a1d2e; border-radius: 10px; padding: 1.2rem 1.8rem; min-width: 140px; text-align: center; border: 1px solid #2a2d3e; }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  .card .label {{ font-size: 0.75rem; color: #888; margin-top: 4px; text-transform: uppercase; }}
  .critical {{ color: #e74c3c; }} .high {{ color: #e67e22; }}
  .medium {{ color: #f1c40f; }} .low {{ color: #3498db; }}
  .total {{ color: #00d4ff; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d2e; border-radius: 10px; overflow: hidden; }}
  th {{ background: #12151f; color: #888; font-size: 0.75rem; text-transform: uppercase; padding: 0.8rem 1rem; text-align: left; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #2a2d3e; font-size: 0.88rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1f2235; }}
  .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; color: #000; }}
  a {{ color: #00d4ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .firmware-path {{ background: #1a1d2e; border-radius: 8px; padding: 0.6rem 1rem; font-family: monospace; font-size: 0.85rem; color: #00d4ff; margin-bottom: 2rem; border: 1px solid #2a2d3e; }}
</style>
</head>
<body>
  <h1>⚡ Firmware Vulnerability Report</h1>
  <div class="meta">Scan date: {scan_date}</div>
  <div class="firmware-path">📁 {firmware_path}</div>

  <div class="cards">
    <div class="card"><div class="num total">{total}</div><div class="label">Total</div></div>
    <div class="card"><div class="num critical">{summary.get('CRITICAL', 0)}</div><div class="label">Critical</div></div>
    <div class="card"><div class="num high">{summary.get('HIGH', 0)}</div><div class="label">High</div></div>
    <div class="card"><div class="num medium">{summary.get('MEDIUM', 0)}</div><div class="label">Medium</div></div>
    <div class="card"><div class="num low">{summary.get('LOW', 0)}</div><div class="label">Low</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>CVE</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved → {output_path}")

def print_summary(findings: list, summary: dict):
    print("\n" + "="*50)
    print("       FIRMWARE VULNERABILITY SCANNER")
    print("="*50)
    print(f"  Scan date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total     : {len(findings)} findings")
    print("-"*50)
    print(f"  CRITICAL  : {summary.get('CRITICAL', 0)}")
    print(f"  HIGH      : {summary.get('HIGH', 0)}")
    print(f"  MEDIUM    : {summary.get('MEDIUM', 0)}")
    print(f"  LOW       : {summary.get('LOW', 0)}")
    print("="*50)
    print("\n[!] Top findings:\n")
    for f in findings[:10]:
        severity = f.get("severity", "?")
        ftype    = f.get("type", f.get("cve_id", "unknown"))
        detail   = f.get("match", f.get("description", f.get("file", "")))[:60]
        print(f"  [{severity}] {ftype} — {detail}")