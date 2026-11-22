#!/bin/bash
# run as root on the vps. installs docker if missing, starts bf2 + bf2am
set -e
cd "$(dirname "$0")"
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sh
[ -f .env ] || echo "RCON_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -dc A-Za-z0-9)" > .env
. ./.env
mkdir -p admin shared
printf 'port=4711\npassword=%s\n' "$RCON_PASSWORD" > admin/default.cfg
docker compose up -d --build
echo "udp 16567 and 29900 need to be open if you run a firewall"
echo "logs: docker compose logs -f"
