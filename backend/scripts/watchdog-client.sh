#!/bin/bash
# Client-side script to automate watchdog pingback over SSH
# Usage: ./watchdog-client.sh <server_ip> <ssh_user> <ssh_key_path> <secret>

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <server_ip> <ssh_user> <ssh_key_path> <secret>"
    exit 1
fi

SERVER_IP=$1
SSH_USER=$2
SSH_KEY=$3
SECRET=$4

MAX_ATTEMPTS=12
SLEEP_INTERVAL=5
ATTEMPT=1

echo "Starting watchdog pingback loop..."

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    echo "Attempt $ATTEMPT of $MAX_ATTEMPTS..."
    
    # Generate timestamp and HMAC-SHA256 signature
    TIMESTAMP=$(date +%s)
    
    # Note: On macOS, use `shasum -a 256`, on Linux use `sha256sum`.
    # Using python to ensure cross-platform consistency for HMAC generation.
    SIGNATURE=$(python3 -c "
import hmac, hashlib
print(hmac.new(b'$SECRET', b'$TIMESTAMP', hashlib.sha256).hexdigest())
")

    PAYLOAD="HEARTBEAT:$TIMESTAMP:$SIGNATURE"
    
    # Send payload via SSH using socat on the server side
    ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -i "$SSH_KEY" "$SSH_USER@$SERVER_IP" \
        "echo '$PAYLOAD' | socat - UNIX-CONNECT:/var/run/mtgroup_watchdog.sock"
    
    # Check if SSH command was successful
    if [ $? -eq 0 ]; then
        echo "Successfully delivered heartbeat to watchdog!"
        exit 0
    else
        echo "Failed to connect or deliver heartbeat. Retrying in $SLEEP_INTERVAL seconds..."
        sleep $SLEEP_INTERVAL
    fi
    
    ATTEMPT=$((ATTEMPT + 1))
done

echo "CRITICAL: Failed to deliver heartbeat after $MAX_ATTEMPTS attempts."
echo "The server's watchdog will likely trigger a rollback soon."
exit 1
