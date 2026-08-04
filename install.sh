#!/bin/bash
# MTGroup VPN Ultimate - Installer Script (Graceful Degradation Edition)

set -e

FORCE=0
for arg in "$@"; do
    if [ "$arg" == "--force" ]; then
        FORCE=1
    fi
done

echo "=========================================================="
echo "🛡️  XDP-SPECTRE (Singularity Edition) Bootstrap Loader  🛡️"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo ./install.sh)"
  exit 1
fi

EBPF_ENABLED="false"
OS_NAME=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')

# 1. Generic OS Dependencies & Watchdog Setup
if [[ "$OS_NAME" == "ubuntu" || "$OS_NAME" == "debian" ]]; then
    echo "Installing core dependencies (socat)..."
    apt-get update && apt-get install -y socat
fi

echo "Setting up Anti-Lockout Watchdog..."
mkdir -p /etc/mtgroup
mkdir -p /var/lib/mtgroup/snapshots
if [ ! -f /etc/mtgroup/watchdog.secret ]; then
    python3 -c "import secrets; print(secrets.token_hex(64))" > /etc/mtgroup/watchdog.secret
    chmod 600 /etc/mtgroup/watchdog.secret
    echo "Generated new watchdog secret."
fi
cp backend/scripts/watchdog.service /etc/systemd/system/mtgroup-watchdog.service
systemctl daemon-reload
systemctl enable mtgroup-watchdog.service
systemctl restart mtgroup-watchdog.service

# 1.5. OS Check & eBPF Installation
if [[ "$OS_NAME" == "ubuntu" || "$OS_NAME" == "debian" ]]; then
    echo "[1/4] Debian/Ubuntu detected. Checking eBPF (BCC) support..."
    
    if apt-get update && apt-get install -y bpfcc-tools linux-headers-$(uname -r) clang llvm build-essential python3-bpfcc python3-pip; then
        echo "✅ Dependencies installed."
        
        if [ -f "Makefile" ]; then
            make clean && make
            if [ $? -eq 0 ]; then
                echo "✅ XDP-Spectre C module compiled."
                
                # Real XDP attach/detach test on loopback
                cat << 'EOF' > ebpf_test.py
try:
    from bcc import BPF
    bpf_text = "int xdp_dummy(struct xdp_md *ctx) { return XDP_PASS; }"
    b = BPF(text=bpf_text)
    fn = b.load_func("xdp_dummy", BPF.XDP)
    b.attach_xdp("lo", fn, 0)
    b.remove_xdp("lo", 0)
    print("SUCCESS")
except Exception as e:
    print(f"FAILED: {e}")
EOF
                TEST_RES=$(python3 ebpf_test.py)
                rm ebpf_test.py
                
                if [[ "$TEST_RES" == *"SUCCESS"* ]]; then
                    EBPF_ENABLED="true"
                    echo "✅ eBPF runtime XDP attach test passed. Advanced protections ENABLED."
                else
                    echo "⚠️ eBPF runtime test failed ($TEST_RES). Advanced protections DISABLED."
                fi
            else
                echo "⚠️ Makefile compilation failed. Advanced protections DISABLED."
            fi
        else
            echo "⚠️ Makefile not found. Advanced protections DISABLED."
        fi
    else
        echo "⚠️ Failed to install BCC tools. Advanced protections DISABLED."
    fi
else
    echo "[1/4] OS is not Debian/Ubuntu ($OS_NAME). Skipping eBPF. Advanced protections DISABLED."
fi

# 2. Docker Compose Configuration (Override approach)
if [ "$EBPF_ENABLED" == "false" ]; then
    echo "Adapting Docker Swarm config via docker-compose.override.yml (reducing attack surface)..."
    cat << 'EOF' > docker-compose.override.yml
version: '3.8'
services:
  vpn-backend:
    network_mode: "bridge"
    ports:
      - "8443:8443"
      - "443:443"
      - "80:80"
    cap_drop:
      - ALL
EOF
else
    # If eBPF is enabled, ensure we don't accidentally leave an old override file breaking things
    if [ -f "docker-compose.override.yml" ]; then
        echo "eBPF is active. Removing old docker-compose.override.yml..."
        rm docker-compose.override.yml
    fi
fi

# 3. Environment Generation (Idempotent)
echo "[2/4] Generating configuration and keys..."
ENV_FILE=".env"
EXISTING_ENV_KEPT="false"
ADMIN_PASS="(Unchanged)"

# Function to generate REALITY keys
generate_reality_keys() {
    cat << 'EOF' > reality_gen.py
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
priv = x25519.X25519PrivateKey.generate()
pub = priv.public_key()
priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
import base64
print(f"PRIV={base64.urlsafe_b64encode(priv_bytes).decode().rstrip('=')}")
print(f"PUB={base64.urlsafe_b64encode(pub_bytes).decode().rstrip('=')}")
EOF
    KEYS=$(python3 reality_gen.py)
    rm reality_gen.py
    REALITY_PRIV=$(echo "$KEYS" | grep PRIV= | cut -d= -f2)
    REALITY_PUB=$(echo "$KEYS" | grep PUB= | cut -d= -f2)
}

if [ -f "$ENV_FILE" ] && [ "$FORCE" -eq 0 ]; then
    echo "⚠️ Existing .env found. Keeping old configuration (use --force to overwrite)."
    EXISTING_ENV_KEPT="true"
    
    # Still update EBPF_ENABLED depending on our test result
    sed -i "s/^EBPF_ENABLED=.*/EBPF_ENABLED=$EBPF_ENABLED/" $ENV_FILE
    
    # Idempotency check: If REALITY_PUBLIC_KEY is entirely missing from .env, append it.
    if ! grep -q "^REALITY_PUBLIC_KEY=" $ENV_FILE; then
        echo "Missing REALITY keys in existing .env. Generating them..."
        generate_reality_keys
        echo "REALITY_PRIVATE_KEY=$REALITY_PRIV" >> $ENV_FILE
        echo "REALITY_PUBLIC_KEY=$REALITY_PUB" >> $ENV_FILE
    elif grep -q "^REALITY_PUBLIC_KEY=$" $ENV_FILE; then
        # It's present but empty
        echo "REALITY keys empty in existing .env. Generating them..."
        generate_reality_keys
        sed -i "s/^REALITY_PRIVATE_KEY=.*/REALITY_PRIVATE_KEY=$REALITY_PRIV/" $ENV_FILE
        sed -i "s/^REALITY_PUBLIC_KEY=.*/REALITY_PUBLIC_KEY=$REALITY_PUB/" $ENV_FILE
    fi

else
    echo "Creating new .env file..."
    cp .env.example $ENV_FILE
    
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
    DB_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    generate_reality_keys

    sed -i "s/CHANGE_ME_SECURE_PASSWORD/$ADMIN_PASS/" $ENV_FILE
    sed -i "s/CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING/$JWT_SECRET/" $ENV_FILE
    sed -i "s/^DB_ENCRYPTION_KEY=.*/DB_ENCRYPTION_KEY=$DB_KEY/" $ENV_FILE
    sed -i "s/^EBPF_ENABLED=.*/EBPF_ENABLED=$EBPF_ENABLED/" $ENV_FILE
    
    # In .env.example they are just placeholders, we can replace or append.
    # We append to be safe or replace if they exist empty.
    if grep -q "^REALITY_PUBLIC_KEY=" $ENV_FILE; then
        sed -i "s/^REALITY_PRIVATE_KEY=.*/REALITY_PRIVATE_KEY=$REALITY_PRIV/" $ENV_FILE
        sed -i "s/^REALITY_PUBLIC_KEY=.*/REALITY_PUBLIC_KEY=$REALITY_PUB/" $ENV_FILE
    else
        echo "REALITY_PRIVATE_KEY=$REALITY_PRIV" >> $ENV_FILE
        echo "REALITY_PUBLIC_KEY=$REALITY_PUB" >> $ENV_FILE
    fi
fi

chmod 600 $ENV_FILE

echo "[3/4] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages || pip3 install -r requirements.txt

echo "[4/4] Setting up SQLite Database..."
cat << 'EOF' > init_db.py
import asyncio
import os
from backend.app.models import Base
from backend.app.core.config import settings
from sqlalchemy.ext.asyncio import create_async_engine

async def main():
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    asyncio.run(main())
EOF
python3 init_db.py
rm init_db.py

# Source .env to get variables for summary, including the just-generated REALITY keys
set -a; source $ENV_FILE; set +a

echo "=========================================================="
echo "🚀 Bootstrap Complete! MTGroup VPN Ultimate is ready."
echo "=========================================================="
echo "🌐 Panel URL      : $BASE_URL (Default Port: $PORT)"
echo "👤 Admin Username : $ADMIN_USERNAME"
if [ "$EXISTING_ENV_KEPT" == "false" ]; then
    echo "🔑 Admin Password : $ADMIN_PASS"
else
    echo "🔑 Admin Password : (Unchanged from previous install)"
fi
echo "----------------------------------------------------------"
echo "📡 DEFAULT REALITY CONFIGURATION:"
echo "   Public Key  : $REALITY_PUBLIC_KEY"
echo "   Default SNI : $DEFAULT_SNI"
echo "----------------------------------------------------------"
echo "🛡️  eBPF Status    : $EBPF_ENABLED"
if [ "$EBPF_ENABLED" == "true" ]; then
    echo "   (AI Detector, Port Hopper, and XDP Blacklist ACTIVE)"
else
    echo "   (Basic mode. AI & Port Hopper bypassed. App-level decoy active.)"
fi
echo "=========================================================="
echo "Run 'docker compose up -d' to start the swarm!"
