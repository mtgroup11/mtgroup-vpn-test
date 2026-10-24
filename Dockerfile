# ═══════════════════════════════════════════════════════════════
# MTGroup VPN Ultimate — Enterprise Dockerfile
# ═══════════════════════════════════════════════════════════════
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies required for eBPF/XDP compilation and networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    gcc \
    make \
    linux-headers-generic \
    iproute2 \
    nftables \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# The privileged helper only answers peers in this group (SO_PEERCRED check
# in privileged_helper_daemon.py). The image had no such group, so in the
# Docker deployment the helper rejected every request from the backend.
# Fixed gid so docker-compose.yml can run the backend with it as primary
# group.
RUN groupadd --system --gid 10001 mtgroup \
    && useradd --system --uid 10001 --gid mtgroup --no-create-home --shell /usr/sbin/nologin mtgroup

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files (.dockerignore keeps .env, the DB, logs and .git out —
# secrets arrive at runtime through docker-compose's env_file)
COPY . .

# Runtime state (SQLite DB, logs) lives here; docker-compose mounts ./data.
RUN mkdir -p /app/data

EXPOSE 8443

# settings.HOST / settings.PORT (8443) / optional TLS — see backend/app/serve.py.
# This used to start uvicorn on :8000 while every other piece of the stack
# (settings, install.sh's port mapping, the docs) expected :8443.
CMD ["python", "-m", "backend.app.serve"]
