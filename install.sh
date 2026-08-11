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

# 1.6. AmneziaWG Installation & Provisioning
#
# Idempotent and reusable both for the local all-in-one host and for
# bootstrapping a fresh remote node (agent/node_daemon.py's add_peer/
# remove_peer/sync only ever mutate an *existing* awg0.conf — this step
# is what has to create it first). Re-running never rotates an existing
# server key: every peer already handed out is signed against it, so
# regenerating it here would silently break every issued client config.
echo "Setting up AmneziaWG..."
AWG_CONF_DIR="/etc/amnezia/amneziawg"
AWG_CONF="$AWG_CONF_DIR/awg0.conf"
AWG_LISTEN_PORT="${MTGROUP_AWG_PORT:-51820}"
# 10.8.0.0/24 is a very common default for WireGuard-family installers —
# collides in practice with other WireGuard tooling on the same host (a
# real conflict hit while testing this against a box already running
# wg-easy on that exact subnet+port). Override via MTGROUP_AWG_SUBNET if
# so. Assumes a /24: the server takes the first host (.1), matching
# wireguard_peers.py's candidate_addresses() convention.
AWG_SUBNET="${MTGROUP_AWG_SUBNET:-10.8.0.0/24}"
AWG_SERVER_IP="$(echo "$AWG_SUBNET" | cut -d'.' -f1-3).1"
AWG_PREFIX_LEN="${AWG_SUBNET#*/}"
AWG_PUBLIC_KEY=""

if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    echo "AmneziaWG tools already installed."
elif [[ "$OS_NAME" == "ubuntu" ]]; then
    echo "Installing AmneziaWG via the Amnezia PPA (Ubuntu)..."
    # Wrapped as an `if` condition (not a bare && chain) so a PPA/network
    # failure degrades gracefully instead of `set -e` aborting the whole
    # install over a non-essential protocol — same pattern the eBPF
    # install above uses.
    if apt-get install -y software-properties-common python3-launchpadlib gnupg2 "linux-headers-$(uname -r)" \
        && add-apt-repository -y ppa:amnezia/ppa \
        && apt-get update \
        && apt-get install -y amneziawg; then
        echo "✅ AmneziaWG installed."
    else
        echo "⚠️ AmneziaWG install failed — leaving it unconfigured on this host."
    fi
elif [[ "$OS_NAME" == "debian" ]]; then
    echo "Installing AmneziaWG via the Amnezia PPA packages (Debian)..."
    mkdir -p /etc/apt/keyrings
    if apt-get install -y software-properties-common gnupg2 "linux-headers-$(uname -r)" \
        && (gpg --keyserver keyserver.ubuntu.com --recv-keys 57290828 --export | gpg --dearmor -o /etc/apt/keyrings/amnezia.gpg) \
        && echo "deb [signed-by=/etc/apt/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" > /etc/apt/sources.list.d/amnezia.list \
        && apt-get update \
        && apt-get install -y amneziawg; then
        echo "✅ AmneziaWG installed."
    else
        echo "⚠️ AmneziaWG install failed — leaving it unconfigured on this host."
    fi
else
    echo "⚠️ OS is not Debian/Ubuntu ($OS_NAME). Skipping AmneziaWG install — provision it manually if this node needs it."
fi

if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    mkdir -p "$AWG_CONF_DIR"

    if [ -f "$AWG_CONF" ]; then
        echo "Existing AmneziaWG config found at $AWG_CONF — leaving it untouched."
        AWG_PRIVATE_KEY=$(grep '^PrivateKey' "$AWG_CONF" | head -1 | cut -d'=' -f2- | tr -d ' ')
        AWG_PUBLIC_KEY=$(echo "$AWG_PRIVATE_KEY" | awg pubkey 2>/dev/null || true)
    else
        echo "Provisioning new AmneziaWG interface ($AWG_SUBNET, port $AWG_LISTEN_PORT)..."

        # Values below (Jc/Jmin/Jmax/S1/S2/H1-H4, and the subnet unless
        # overridden) match backend/app/models.py's Node column defaults
        # exactly, so a Node row created via the dashboard with default
        # Amnezia settings agrees with what's actually running here
        # without extra config.
        EGRESS_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
        if [ -z "$EGRESS_IF" ]; then
            EGRESS_IF="eth0"
            echo "⚠️ Could not auto-detect the default network interface for NAT — falling back to eth0. Check PostUp/PostDown in $AWG_CONF if outbound traffic doesn't work."
        fi

        AWG_PRIVATE_KEY=$(awg genkey)
        AWG_PUBLIC_KEY=$(echo "$AWG_PRIVATE_KEY" | awg pubkey)

        cat << EOF > "$AWG_CONF"
[Interface]
PrivateKey = $AWG_PRIVATE_KEY
Address = $AWG_SERVER_IP/$AWG_PREFIX_LEN
ListenPort = $AWG_LISTEN_PORT
MTU = 1280
PostUp = iptables -A FORWARD -i awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EGRESS_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EGRESS_IF -j MASQUERADE
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
EOF
        chmod 600 "$AWG_CONF"
    fi

    # Arm the Anti-Lockout Watchdog before bringing the interface up.
    # PostUp touches iptables (FORWARD/NAT) — if that, or anything else
    # about this change, cuts the current session, the watchdog's 60s
    # timeout restores the pre-change iptables state on its own. See
    # backend/app/core/watchdog.py / watchdog_client.py. Needs no pip
    # deps (stdlib only), so this works even before requirements.txt is
    # installed further down.
    WATCHDOG_ARMED=0
    if [ -f /etc/mtgroup/watchdog.secret ]; then
        if python3 -c "from backend.app.core.watchdog_client import snapshot_and_arm; snapshot_and_arm()" 2>/dev/null; then
            WATCHDOG_ARMED=1
        else
            echo "⚠️ Could not arm the watchdog before starting awg0 — proceeding without that safety net."
        fi
    fi

    systemctl enable --now "awg-quick@awg0" || echo "⚠️ Failed to start awg-quick@awg0 — check 'journalctl -u awg-quick@awg0'."

    if [ "$WATCHDOG_ARMED" -eq 1 ]; then
        echo "Watchdog armed for 60s: verify you still have SSH access from a FRESH connection (not this session), or run backend/scripts/watchdog-client.sh, to confirm and disarm — otherwise this change rolls back automatically."
    fi
else
    echo "⚠️ awg/awg-quick still not found — AmneziaWG will remain unconfigured on this host."
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
if [ -n "$AWG_PUBLIC_KEY" ]; then
    echo "🔐 AmneziaWG Server Public Key : $AWG_PUBLIC_KEY"
    echo "   Listen Port                 : $AWG_LISTEN_PORT"
    echo "   Enter these when adding/editing this node in the panel"
    echo "   dashboard ('Amnezia Server Public Key' / port fields)."
else
    echo "🔐 AmneziaWG                   : not provisioned on this host."
fi
echo "----------------------------------------------------------"
echo "🛡️  eBPF Status    : $EBPF_ENABLED"
if [ "$EBPF_ENABLED" == "true" ]; then
    echo "   (AI Detector, Port Hopper, and XDP Blacklist ACTIVE)"
else
    echo "   (Basic mode. AI & Port Hopper bypassed. App-level decoy active.)"
fi
echo "=========================================================="
echo "Run 'docker compose up -d' to start the swarm!"
