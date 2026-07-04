FROM ubuntu:18.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    git build-essential zlib1g-dev liblzma-dev liblzo2-dev wget \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/devttys0/sasquatch /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && sed -i 's/-Werror//' squashfs4.3/squashfs-tools/Makefile 2>/dev/null || true \
    && ./build.sh

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-pip binwalk squashfs-tools \
    zlib1g liblzma5 liblzo2-2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/sasquatch/squashfs4.3/squashfs-tools/sasquatch /usr/local/bin/
RUN pip3 install requests colorama jinja2 python-magic
WORKDIR /app
COPY . .