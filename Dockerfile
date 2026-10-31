# thscan — defensive PHP2Shell scanner for Thai government web assets.
FROM python:3.13-slim AS base

# dnsutils gives operators the familiar `nslookup`/`dig` on the shell too;
# the scanner itself resolves via dnspython.
# nmap + traceroute power "deep mode" (service/version detection + network
# path). Both run as a TCP connect scan / UDP traceroute, so no root is needed;
# fast mode still works with neither installed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils ca-certificates curl nmap traceroute \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    THSCAN_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
# GitHub source archives can be slow on institutional links; retry transient reads.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefer-binary --retries 10 --timeout 180 -r requirements.txt

COPY app ./app
COPY static ./static

# Run as an unprivileged user; the connect-scan needs no special capabilities.
RUN useradd --system --uid 10001 --home-dir /app thscan \
    && mkdir -p /data \
    && chown -R thscan:thscan /app /data
USER thscan

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/healthz" || exit 1

# Honour $PORT when the host assigns one (e.g. Render, Fly, Cloud Run);
# defaults to 8000 for local docker-compose. Shell form so $PORT expands.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
