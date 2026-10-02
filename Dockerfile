# syntax=docker/dockerfile:1
#
# qa-agent, packaged for on-premise / air-gapped use.
#
# The build is the ONLY step that uses the internet. Everything a scan needs is
# baked in here - scanner binaries, Semgrep rule packs, the Trivy and OSV
# vulnerability databases, Lighthouse and Chromium - so the running container
# needs no network access beyond the target application and the local model.

ARG PLAYWRIGHT_VERSION=1.63.0
ARG TRIVY_VERSION=0.74.0
ARG OSV_VERSION=2.6.0
ARG LIGHTHOUSE_VERSION=13.5.0

# ---------------------------------------------------------------------------
# Scanner binaries, pinned and verified against the publishers' checksums.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS scanners
ARG TRIVY_VERSION
ARG OSV_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eux; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy
RUN set -eux; \
    base="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}"; \
    curl -fsSLO "${base}/osv-scanner_linux_amd64"; \
    curl -fsSLO "${base}/osv-scanner_SHA256SUMS"; \
    grep " osv-scanner_linux_amd64\$" osv-scanner_SHA256SUMS | sha256sum -c -; \
    mv osv-scanner_linux_amd64 osv-scanner; \
    chmod +x osv-scanner

# ---------------------------------------------------------------------------
# Lighthouse, installed locally so npx never downloads it at scan time.
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS lighthouse
ARG LIGHTHOUSE_VERSION
RUN npm install --prefix /opt/lighthouse "lighthouse@${LIGHTHOUSE_VERSION}" --no-audit --no-fund

# ---------------------------------------------------------------------------
# The agent. The Playwright image already ships Chromium and its libraries.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble
ARG PLAYWRIGHT_VERSION

# The image ships browsers and git but neither venv nor the Python package.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QA_AGENT_DATA_DIR=/opt/qa-agent-data \
    PATH=/opt/venv/bin:$PATH

# Node for Lighthouse, the Docker CLI for ZAP, and the two scanners.
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=scanners /dl/trivy /dl/osv-scanner /usr/local/bin/
COPY --from=lighthouse /opt/lighthouse /opt/qa-agent-data/tools/lighthouse

WORKDIR /app
COPY pyproject.toml README.md ./
COPY qa_agent ./qa_agent
# Pin Playwright to the browsers baked into the base image.
RUN python3 -m venv /opt/venv \
 && pip install --no-cache-dir ".[scanners]" "playwright==${PLAYWRIGHT_VERSION}"

# Provision the offline data into the image: rule packs and vulnerability
# databases. The ZAP image is a sibling container, pulled on the host instead.
RUN qa-agent seed --component semgrep --component trivy --component osv

# Scan results are the only thing that must survive the container.
VOLUME ["/opt/qa-agent-data/workspace"]

ENTRYPOINT ["python", "-m", "qa_agent"]
CMD ["check_env"]
