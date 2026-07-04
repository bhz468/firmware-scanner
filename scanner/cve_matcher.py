import re
import os
import requests
import subprocess

BLACKLIST = {
    "version", "Version", "revision", "release", "build", "patch",
    "using", "list", "unknown", "with", "and", "And", "the", "The",
    "from", "for", "not", "are", "this", "that", "have", "been",
    "ipaddr", "netmask", "least", "PPDU", "IEEE", "HotSpot", "balance",
    "HE", "LTF", "udhcp"
}

KNOWN_COMPONENTS = {
    "busybox", "BusyBox", "linux", "openssl", "OpenSSL", "dropbear",
    "curl", "wget", "dnsmasq", "hostapd", "wpa", "openwrt", "uclibc",
    "musl", "iptables", "ppp", "xl2tpd", "openssh", "lighttpd", "uhttpd"
}

def extract_versions(rootfs_path: str) -> list:
    versions = []
    seen = set()
    for root, _, files in os.walk(rootfs_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                out = subprocess.run(
                    ["strings", fpath],
                    capture_output=True, text=True, timeout=10
                ).stdout
                matches = re.findall(r'([A-Za-z][\w-]{2,})\s+v?(\d+\.\d+[\.\d]*)', out)
                for component, version in matches:
                    if component in BLACKLIST:
                        continue
                    if len(component) < 3:
                        continue
                    if version in {"0.0.0.0", "127.0.0.1", "255.0.0.0"}:
                        continue
                    # Prioritise known components
                    key = f"{component.lower()}_{version}"
                    if key not in seen:
                        seen.add(key)
                        versions.append({
                            "component": component,
                            "version": version,
                            "file": fpath,
                            "priority": component.lower() in {c.lower() for c in KNOWN_COMPONENTS}
                        })
            except Exception:
                pass
    # Sort: known components first
    versions.sort(key=lambda x: not x.get("priority", False))
    return versions

def query_nvd(component: str, version: str) -> list:
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={component}+{version}"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        cves = r.json().get("vulnerabilities", [])
        results = []
        for v in cves[:3]:
            cve = v["cve"]
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            desc = cve["descriptions"][0]["value"]
            if component.lower() not in desc.lower():
                continue
            results.append({
                "type": "cve",
                "cve_id": cve["id"],
                "component": component,
                "version": version,
                "description": desc[:150],
                "severity": cvss.get("baseSeverity", "UNKNOWN")
            })
        return results
    except Exception:
        return []