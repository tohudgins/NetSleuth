# NetSleuth — defensive, educational network toolkit. Authorized use only.
#
# Build:  docker build -t netsleuth .
# Scan:   docker run --rm netsleuth 127.0.0.1 -p 1-1024 --connect
#
# Raw sockets (SYN scan, live capture) need extra capabilities:
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN netsleuth <target> --sniff
#
# The web UI binds to loopback only by design, so run it on the host network
# (then browse http://127.0.0.1:8765):
#   docker run --rm --network host --entrypoint netsleuth-web netsleuth
# NOTE: --network host shares the HOST's loopback only on Linux. On macOS/Windows
# Docker Desktop it maps the VM's loopback, so the UI is unreachable from the
# browser — run `netsleuth-web` natively there instead (see README "Run with Docker").
FROM python:3.12-slim

# libpcap helps scapy on Linux; keep the image slim otherwise.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

ENTRYPOINT ["netsleuth"]
CMD ["--help"]
