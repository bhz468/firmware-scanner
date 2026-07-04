# Firmware Vulnerability Scanner

> A static analysis security tool that automatically extracts and audits IoT/router firmware binaries for vulnerabilities — no hardware required.

## What it does

Most IoT devices (routers, cameras, smart home devices) run embedded Linux firmware that contains hardcoded credentials, outdated libraries with known CVEs, and binaries compiled without basic security protections. This tool automates the process of finding these issues.

Given a `.bin` firmware file, the scanner:
1. Extracts the filesystem using binwalk and sasquatch
2. Hunts for hardcoded secrets (passwords, private keys, API keys)
3. Matches detected software versions against the NVD CVE database
4. Checks ELF binaries for missing security protections
5. Generates a scored HTML report with severity levels

## Real findings

Tested on real router firmware downloaded from official manufacturer websites:

| Firmware | Size | Findings | Critical | High |
|----------|------|----------|----------|------|
| TP-Link Archer C7 v2 | 16MB | 5 | 0 | 1 |
| TP-Link WR841HP v2 | 8MB | 5 | 0 | 1 |
| Netgear WNDR3700 v2 | 6MB | 0 | 0 | 0 |

**Notable finding:** `password='password'` hardcoded in TP-Link Archer C7 uhttpd configuration — a default credential that could allow unauthorized admin access if the user never changes it.

## Architecture
firmware-scanner/

├── scanner/

│   ├── extractor.py         # binwalk + sasquatch extraction engine

│   ├── credential_hunter.py # regex-based secrets detection

│   ├── cve_matcher.py       # NVD API v2 CVE lookup

│   ├── binary_hardening.py  # ELF security checks (NX, RELRO, PIE, canary)

│   ├── risk_scorer.py       # CVSS-inspired severity scoring

│   └── report.py            # JSON + HTML report generation

├── main.py                  # orchestrator with ThreadPoolExecutor

├── Dockerfile               # multi-stage build (Ubuntu 18.04 + 20.04)

└── scan_all.sh              # batch scanning script

## How it works

### 1. Extraction
Uses `binwalk` to identify and extract compressed sections from the binary. For non-standard SquashFS formats (common in older routers), falls back to `sasquatch` — a patched version of unsquashfs that supports vendor-modified compression.

### 2. Credential hunting
Scans text files in the extracted filesystem using regex patterns for:
- Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- Hardcoded passwords (`password='...'`)
- AWS access keys (`AKIA...`)
- API keys and tokens

Skips binary files, JS/CSS assets, and locale files to minimize false positives.

### 3. CVE matching
Extracts version strings from binaries using `strings`, filters out generic words (version, build, release), and queries the NVD API v2 for known vulnerabilities. Results are deduplicated and filtered to only include CVEs that mention the component name in their description.

### 4. Binary hardening
Runs `greadelf` on every ELF binary to check for:
- **NX bit** — non-executable stack
- **RELRO** — read-only relocations (GOT protection)
- **Stack canary** — buffer overflow detection
- **PIE** — position independent executable (ASLR support)

### 5. Scoring and reporting
Findings are ranked by severity (CRITICAL → HIGH → MEDIUM → LOW) and output as both JSON (machine-readable) and HTML (visual dashboard with CVE links).

## Usage

```bash
# Build the Docker image (compiles sasquatch from source)
docker build -t firmware-scanner .

# Scan a firmware
CONTAINER=$(docker create firmware-scanner sleep 9999)
docker start $CONTAINER
docker cp firmware.bin $CONTAINER:/tmp/fw.bin
docker exec $CONTAINER python3 main.py /tmp/fw.bin --output /tmp/report.json
docker cp $CONTAINER:/tmp/report.html ./report.html
docker cp $CONTAINER:/tmp/report.json ./report.json
docker stop $CONTAINER && docker rm $CONTAINER

# Open the report
open report.html
```

## Tech stack

| Component | Purpose |
|-----------|---------|
| Python 3 | Core scanner logic |
| Docker (multi-stage) | Isolated environment, sasquatch compilation |
| binwalk | Firmware extraction and signature detection |
| sasquatch | Non-standard SquashFS extraction |
| squashfs-tools | Standard SquashFS extraction |
| greadelf (binutils) | ELF binary analysis |
| NVD API v2 | CVE database queries |
| SQLite | Result caching for instant re-scans |
| ThreadPoolExecutor | Parallel analysis modules |

## Supported formats

- SquashFS 4.x (standard) — full support
- SquashFS 3.x (non-standard, vendor-modified) — partial support via sasquatch
- TRX firmware images (Broadcom routers)
- LZMA/gzip compressed kernels

## Limitations

- Very old firmware with proprietary compression (pre-2015) may not extract fully
- CVE matching relies on string detection — version numbers embedded deep in binaries may be missed
- NVD API rate limits apply (no API key required for basic use)
