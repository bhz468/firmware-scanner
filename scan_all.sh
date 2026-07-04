#!/bin/bash

FIRMWARES=(
    "netgear_wndr3700.bin"
    "tplink_archerc7.bin"
    "openwrt-23.05.6-ath79-generic-tplink_tl-wr841hp-v2-squashfs-factory.bin"
)

mkdir -p ~/Desktop/firmware-scanner/reports

for fw in "${FIRMWARES[@]}"; do
    name=$(basename "$fw" .bin)
    echo "========================================"
    echo "Scanning: $name"
    echo "========================================"

    # Crée un container, copie le firmware dedans, scanne
    CONTAINER=$(docker create firmware-scanner sleep 999)
    docker cp ~/Desktop/${fw} ${CONTAINER}:/tmp/${fw}
    docker start ${CONTAINER}
    docker exec ${CONTAINER} python3 main.py /tmp/${fw} --output /tmp/${name}_report.json
    docker cp ${CONTAINER}:/tmp/${name}_report.json ~/Desktop/firmware-scanner/reports/${name}_report.json 2>/dev/null
    docker cp ${CONTAINER}:/tmp/${name}_report.html ~/Desktop/firmware-scanner/reports/${name}_report.html 2>/dev/null
    docker stop ${CONTAINER} && docker rm ${CONTAINER}

    echo ""
done

echo "Done! Reports:"
ls ~/Desktop/firmware-scanner/reports/
