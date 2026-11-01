# thscan — defensive PHP2Shell & multi-CVE scanner.
FROM python:3.13-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils ca-certificates curl nmap traceroute \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    THSCAN_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefer-binary --retries 10 --timeout 180 -r requirements.txt

COPY security_audit_toolkit.py ./security_audit_toolkit.py
COPY app ./app
COPY static ./static

RUN useradd --system --uid 10001 --home-dir /app thscan \
    && mkdir -p /data \
    && chown -R thscan:thscan /app /data
USER thscan

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
