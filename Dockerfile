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

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose API port (though network_mode: host makes this informational)
EXPOSE 8000

# Start the application using Uvicorn
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
