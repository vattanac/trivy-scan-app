# syntax=docker/dockerfile:1.6
#
# Trivy Docker Image Scanner — runtime container
#
# Build:   docker build -t trivy-image-scanner:latest .
# Run:     docker run --rm -p 8000:8000 \
#              -v /var/run/docker.sock:/var/run/docker.sock \
#              -v "$(pwd)/tars:/app/tars" \
#              trivy-image-scanner:latest
# Open:    http://localhost:8000
#
FROM python:3.12-slim

# ---- OS-level dependencies ----------------------------------------------------
# - curl, ca-certificates, tar, gzip: needed to fetch Trivy + Docker CLI binaries
# - tini: clean PID-1 signal handling (Ctrl+C, docker stop)
# We install only the Docker *client* (no daemon) — the container talks to the
# host's Docker engine via a mounted /var/run/docker.sock.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates curl tar gzip tini \
    && rm -rf /var/lib/apt/lists/*

# ---- Docker CLI --------------------------------------------------------------
ARG DOCKER_VERSION=27.3.1
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  pkg_arch="x86_64"  ;; \
      aarch64) pkg_arch="aarch64" ;; \
      *) echo "Unsupported arch: $arch" && exit 1 ;; \
    esac; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${pkg_arch}/docker-${DOCKER_VERSION}.tgz" \
        -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    docker --version

# ---- Trivy binary (pre-installed so the UI doesn't need to download it) ------
# Use Trivy's official installer — it handles arch detection and any future
# asset-naming changes automatically. Pin to a tag, or pass --build-arg
# TRIVY_VERSION=latest at build time to grab the newest stable release.
ARG TRIVY_VERSION=0.69.3
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  pkg_arch="64bit"   ;; \
      aarch64) pkg_arch="ARM64"   ;; \
      *) echo "Unsupported arch: $arch" && exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${pkg_arch}.tar.gz" \
        -o /tmp/trivy.tgz; \
    tar -xzf /tmp/trivy.tgz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy.tgz /tmp/trivy; \
    trivy --version

# ---- Python dependencies (cache layer separately from app source) ------------
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ---- App source --------------------------------------------------------------
# Only copy the files that make up the app. The .dockerignore prevents
# accidental inclusion of venv/, bin/, tars/, .git/, etc.
COPY main.py index.html README.md ./

# Writable output + binary directories (mount these as volumes for persistence)
RUN mkdir -p /app/tars /app/bin /root/.cache/trivy

# ---- Runtime config ----------------------------------------------------------
# Bind to 0.0.0.0 inside the container so the published port is reachable.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1
EXPOSE 8000

# Healthcheck: hit / to verify uvicorn is serving
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:${PORT}/ >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "main.py"]
