#!/bin/bash
set -e

SELF_IP=$(hostname -I | tr ' ' '\n' | grep '^10\.255\.' | grep -v '^10\.255\.254\.' | head -n1)
PREFIX=$(echo "$SELF_IP" | cut -d. -f1-3)
ATTACK_SUBNET="$PREFIX.0/24"
ATTACK_GW="$PREFIX.1"
echo "$ATTACK_GW,$SELF_IP" > /etc/nmap-exclude

# Initialize Searchsploit database if not already done
if [ ! -f "/root/.searchsploit_rc" ]; then
    echo "[INFO] Initializing searchsploit database..."
    searchsploit -u > /dev/null 2>&1 || true
fi

exec "$@"