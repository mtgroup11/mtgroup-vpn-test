#!/bin/bash
# MTGroup VPN Ultimate — node agent installer
#
# Run on each VPN node, from a checkout of this repository:
#
#   sudo MTGROUP_NODE_API_KEY='<from the panel>' bash agent/install_agent.sh
#
# The API key comes from the panel: GET /api/nodes/<id>/agent-setup returns
# it together with this exact command. Re-running is safe: the TLS
# certificate and the existing key are kept unless you pass a new key.
#
# At the end the agent's certificate is printed. Paste it into the node's
# `agent_cert_pem` in the panel so the panel pins *this* certificate rather
# than trusting whatever answers on first contact.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Run as root (sudo)." >&2
    exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/mtgroup-agent"
ETC_DIR="/etc/mtgroup-agent"
ENV_FILE="$ETC_DIR/agent.env"
UNIT_FILE="/etc/systemd/system/mtgroup-node-agent.service"
PORT="${MTGROUP_NODE_PORT:-8443}"

if [ -z "${MTGROUP_NODE_API_KEY:-}" ]; then
    if [ -f "$ENV_FILE" ] && grep -q '^MTGROUP_NODE_API_KEY=.' "$ENV_FILE"; then
        echo "Keeping the API key already in $ENV_FILE."
        MTGROUP_NODE_API_KEY="$(grep '^MTGROUP_NODE_API_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
    else
        echo "❌ MTGROUP_NODE_API_KEY is not set. Get it from the panel (GET /api/nodes/<id>/agent-setup)." >&2
        exit 1
    fi
fi
case "$MTGROUP_NODE_API_KEY" in
    *[!A-Za-z0-9_-]*) echo "❌ MTGROUP_NODE_API_KEY has unexpected characters." >&2; exit 1 ;;
esac
case "$PORT" in
    ''|*[!0-9]*) echo "❌ MTGROUP_NODE_PORT must be a number." >&2; exit 1 ;;
esac

# ── Hysteria2 / TUIC nodes: sing-box + a real certificate ────────────────
# Set MTGROUP_TLS_DOMAIN (the panel's agent-setup command does, for those
# nodes) to a domain whose DNS A/AAAA record points at this server — with
# any CDN proxy (Cloudflare's orange cloud) OFF, since both are UDP.
# The certificate comes from Let's Encrypt over HTTP-01, so TCP 80 must be
# reachable from the internet while this runs and at each renewal.
TLS_DOMAIN="${MTGROUP_TLS_DOMAIN:-}"
# Not under $ETC_DIR (0700 root): newer sing-box packages run as user sing-box.
PUBLIC_TLS_DIR="/etc/sing-box/mtgroup-tls"
if [ -n "$TLS_DOMAIN" ]; then
    if ! echo "$TLS_DOMAIN" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'; then
        echo "❌ MTGROUP_TLS_DOMAIN must be a plain lower-case domain name." >&2
        exit 1
    fi
    if ! command -v sing-box >/dev/null 2>&1; then
        echo "Installing sing-box from the official SagerNet apt repository..."
        apt-get update && apt-get install -y curl gnupg
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
        chmod a+r /etc/apt/keyrings/sagernet.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" \
            > /etc/apt/sources.list.d/sagernet.list
        apt-get update && apt-get install -y sing-box
    fi
    command -v certbot >/dev/null 2>&1 || { apt-get update && apt-get install -y certbot; }

    # Copies the live certificate to fixed paths the panel's sing-box config
    # points at, and reloads sing-box — on first issue and every renewal.
    HOOK=/etc/letsencrypt/renewal-hooks/deploy/mtgroup-sing-box.sh
    mkdir -p "$(dirname "$HOOK")" "$PUBLIC_TLS_DIR"
    cat > "$HOOK" <<EOF
#!/bin/sh
set -e
[ "\$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$TLS_DOMAIN" ] || exit 0
install -m 600 "\$RENEWED_LINEAGE/fullchain.pem" "$PUBLIC_TLS_DIR/fullchain.pem"
install -m 600 "\$RENEWED_LINEAGE/privkey.pem" "$PUBLIC_TLS_DIR/privkey.pem"
if id sing-box >/dev/null 2>&1; then chown -R sing-box: "$PUBLIC_TLS_DIR"; fi
systemctl restart sing-box || true
EOF
    chmod 755 "$HOOK"

    echo "Requesting a Let's Encrypt certificate for $TLS_DOMAIN (needs TCP 80 open)..."
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email --keep-until-expiring -d "$TLS_DOMAIN"
    RENEWED_LINEAGE="/etc/letsencrypt/live/$TLS_DOMAIN" "$HOOK"
    systemctl enable sing-box >/dev/null 2>&1 || true
    echo "✅ Certificate for $TLS_DOMAIN installed; certbot renews it automatically."
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Installing python3..."
    apt-get update && apt-get install -y python3 python3-venv
fi
if ! python3 -c "import venv" >/dev/null 2>&1; then
    apt-get update && apt-get install -y python3-venv
fi

echo "Installing agent into $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/agent"
mkdir -p "$INSTALL_DIR/agent"
cp "$SRC_DIR"/__init__.py "$SRC_DIR"/node_daemon.py "$SRC_DIR"/watchdog_client.py "$INSTALL_DIR/agent/"

if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet "aiohttp>=3.10.0" "psutil>=6.1.0" "cryptography>=43.0.0"

mkdir -p "$ETC_DIR"
chmod 700 "$ETC_DIR"
umask 077
cat > "$ENV_FILE" <<EOF
MTGROUP_NODE_API_KEY=$MTGROUP_NODE_API_KEY
MTGROUP_NODE_PORT=$PORT
MTGROUP_NODE_TLS_DIR=$ETC_DIR/tls
EOF
chmod 600 "$ENV_FILE"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=MTGroup VPN node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python -m agent.node_daemon
Restart=always
RestartSec=5
# Runs as root: it rewrites the Xray / AmneziaWG configs and restarts those
# services. It only acts on requests signed with the panel's key.
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create the certificate now (idempotent) so it can be printed below.
set -a; . "$ENV_FILE"; set +a
(cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" -m agent.node_daemon --print-cert > "$ETC_DIR/agent-cert.pem")

systemctl daemon-reload
systemctl enable mtgroup-node-agent.service >/dev/null
systemctl restart mtgroup-node-agent.service

sleep 2
if systemctl is-active --quiet mtgroup-node-agent.service; then
    echo "✅ Agent running on TCP $PORT (HTTPS)."
else
    echo "⚠️ Agent did not start — check: journalctl -u mtgroup-node-agent -n 50" >&2
fi

echo "----------------------------------------------------------"
echo "Allow the panel to reach TCP $PORT on this node (and only the panel, if you can)."
if [ -n "$TLS_DOMAIN" ]; then
    echo "Open the node's VPN port for UDP (Hysteria2/TUIC), and keep TCP 80 open for certificate renewals."
fi
echo "Then paste this certificate into the node's 'agent_cert_pem' in the panel:"
echo
cat "$ETC_DIR/agent-cert.pem"
echo
(cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" -m agent.node_daemon --print-cert 2>&1 >/dev/null)
echo "----------------------------------------------------------"
