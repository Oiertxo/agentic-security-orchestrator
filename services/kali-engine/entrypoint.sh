#!/bin/bash
echo "[ENTRYPOINT] Started at $(date +"%T.%3N")"
set -ex

SELF_IP=$(hostname -I | tr ' ' '\n' | grep '^10\.255\.' | grep -v '^10\.255\.254\.' | head -n1)
echo "[ENTRYPOINT] Got SELF_IP=$SELF_IP at $(date +"%T.%3N")"
PREFIX=$(echo "$SELF_IP" | cut -d. -f1-3)
ATTACK_SUBNET="$PREFIX.0/24"
ATTACK_GW="$PREFIX.1"
echo "$ATTACK_GW,$SELF_IP" > /etc/nmap-exclude

echo "[ENTRYPOINT] Executing command at $(date +"%T.%3N")"

exec "$@"