import subprocess
import os
import math
import shutil
import re

def extract_firmware(firmware_path: str, output_dir: str) -> dict:
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    try:
        subprocess.run(
            ["binwalk", "--extract", "--directory", output_dir, firmware_path],
            stdin=open("/dev/null"),
            stdout=open("/dev/null", "w"),
            stderr=open("/dev/null", "w"),
            timeout=120
        )
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["binwalk", firmware_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if "Squashfs" in line:
                match = re.match(r'(\d+)', line.strip())
                if match:
                    offset = int(match.group(1))
                    squashfs_dir = os.path.join(output_dir, "squashfs-root")
                    try:
                        subprocess.run(
                            ["sasquatch", "-d", squashfs_dir, "-o", str(offset), firmware_path],
                            stdin=open("/dev/null"),
                            stdout=open("/dev/null", "w"),
                            stderr=open("/dev/null", "w"),
                            timeout=120
                        )
                    except Exception:
                        pass
    except Exception:
        pass

    return {
        "output_dir": output_dir,
        "success": True
    }

def file_entropy(filepath: str, max_bytes: int = 1024 * 100) -> float:
    with open(filepath, "rb") as f:
        data = f.read(max_bytes)
    if not data:
        return 0.0
    freq = [data.count(bytes([i])) / len(data) for i in range(256)]
    return -sum(p * math.log2(p) for p in freq if p > 0)

def scan_high_entropy(rootfs_path: str, threshold: float = 7.5) -> list:
    suspicious = []
    for root, _, files in os.walk(rootfs_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                entropy = file_entropy(fpath)
                if entropy >= threshold:
                    suspicious.append({
                        "file": fpath,
                        "entropy": round(entropy, 3),
                        "severity": "MEDIUM",
                        "type": "high_entropy"
                    })
            except Exception:
                pass
    return suspicious