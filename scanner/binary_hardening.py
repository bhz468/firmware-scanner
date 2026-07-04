import subprocess
import os

def check_binary(binary_path: str) -> dict:
    try:
        dynamic = subprocess.run(
            ["greadelf", "-d", binary_path],
            capture_output=True, text=True, timeout=10
        ).stdout

        headers = subprocess.run(
            ["greadelf", "-h", binary_path],
            capture_output=True, text=True, timeout=10
        ).stdout

        strings_out = subprocess.run(
            ["strings", binary_path],
            capture_output=True, text=True, timeout=10
        ).stdout

        issues = []

        nx = "GNU_STACK" in dynamic
        if not nx:
            issues.append({
                "type": "no_nx",
                "file": binary_path,
                "severity": "HIGH",
                "match": "NX bit not enabled — stack is executable"
            })

        relro = "BIND_NOW" in dynamic or "RELRO" in dynamic
        if not relro:
            issues.append({
                "type": "no_relro",
                "file": binary_path,
                "severity": "MEDIUM",
                "match": "RELRO not enabled — GOT table is writable"
            })

        canary = "__stack_chk_fail" in strings_out
        if not canary:
            issues.append({
                "type": "no_stack_canary",
                "file": binary_path,
                "severity": "MEDIUM",
                "match": "No stack canary detected"
            })

        pie = "DYN" in headers
        if not pie:
            issues.append({
                "type": "no_pie",
                "file": binary_path,
                "severity": "LOW",
                "match": "PIE not enabled — fixed memory addresses"
            })

        return {"file": binary_path, "issues": issues}

    except Exception:
        return {"file": binary_path, "issues": []}


def check_all_binaries(rootfs_path: str) -> list:
    findings = []
    count = 0
    for root, _, files in os.walk(rootfs_path):
        for fname in files:
            if count >= 20:
                return findings
            fpath = os.path.join(root, fname)
            try:
                result = subprocess.run(
                    ["file", fpath],
                    capture_output=True, text=True, timeout=5
                ).stdout
                if "ELF" in result:
                    data = check_binary(fpath)
                    findings.extend(data["issues"])
                    count += 1
            except Exception:
                pass
    return findings
