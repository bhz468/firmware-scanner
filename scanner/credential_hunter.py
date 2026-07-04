import subprocess
import os
import re

SKIP_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.gif', '.ico', '.mo', '.ttf', '.woff', '.svg'}
SKIP_DIRS = {'lib/modules', 'usr/share/locale'}

PATTERNS = [
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----", "CRITICAL"),
    ("private_key", "-----BEGIN EC PRIVATE KEY-----", "CRITICAL"),
    ("aws_key",     r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    ("password",    r"password\s*=\s*['\"][^'\"]{4,}", "HIGH"),
    ("password",    r"passwd\s*=\s*['\"][^'\"]{4,}", "HIGH"),
    ("api_key",     r"api_key\s*=\s*['\"][^'\"]{8,}", "HIGH"),
]

def is_text_file(filepath: str) -> bool:
    try:
        result = subprocess.run(
            ["file", filepath],
            capture_output=True, text=True, timeout=5
        ).stdout
        return "text" in result.lower() or "script" in result.lower()
    except Exception:
        return False

def hunt_credentials(rootfs_path: str) -> list:
    findings = []

    for root, dirs, files in os.walk(rootfs_path):
        # Skip dossiers inutiles
        dirs[:] = [d for d in dirs if not any(skip in os.path.join(root, d) for skip in SKIP_DIRS)]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)

            # Skip fichiers binaires
            if not is_text_file(fpath):
                continue

            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read(1024 * 256)

                for vuln_type, pattern, severity in PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches[:3]:
                        # Filtre les faux positifs évidents
                        if vuln_type == "password" and len(match) < 10:
                            continue
                        findings.append({
                            "type": vuln_type,
                            "file": fpath.replace(rootfs_path, ""),
                            "match": match[:80],
                            "severity": severity
                        })
            except Exception:
                pass

    return findings