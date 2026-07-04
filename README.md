# Firmware Vulnerability Scanner

A static analysis tool that automatically extracts and scans IoT/router firmware binaries for security vulnerabilities.

## Features

- **Firmware extraction** — supports SquashFS 3.x/4.x, LZMA, gzip via binwalk + sasquatch
- **Credential hunting** — detects hardcoded passwords, private keys, API keys
- **CVE matching** — queries NVD API for known vulnerabilities in detected components
- **Binary hardening** — checks NX, RELRO, stack canary, PIE on ELF binaries
- **Parallel analysis** — concurrent scanning for speed
- **HTML report** — visual dashboard with severity breakdown and CVE links
- **Result caching** — SQLite cache for instant re-scans

## Usage

\`\`\`bash
docker build -t firmware-scanner .
CONTAINER=$(docker create firmware-scanner sleep 9999)
docker start $CONTAINER
docker cp firmware.bin $CONTAINER:/tmp/fw.bin
docker exec $CONTAINER python3 main.py /tmp/fw.bin --output /tmp/report.json
docker cp $CONTAINER:/tmp/report.html ./report.html
docker stop $CONTAINER && docker rm $CONTAINER
\`\`\`

## Tech Stack

Python 3, Docker, binwalk, sasquatch, squashfs-tools, NVD API, SQLite
