#!/usr/bin/env bash
# HipnoType Relay bootstrap. Run as root, from inside this folder.
# Supports Ubuntu 20.04/22.04/24.04 and Debian 11/12/13.
set -Eeuo pipefail
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo bash setup-relay.sh)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/hipno-relay
DOMAIN="${RELAY_DOMAIN:-hipno-relay.mangocloud.cyou}"

echo "[1/6] Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl unzip ca-certificates caddy

echo "[2/6] Installing Bun"
if ! [ -x /usr/local/bin/bun ]; then
  curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr/local bash
fi
/usr/local/bin/bun --version

echo "[3/6] Installing relay files to $APP"
id hipno-relay >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin hipno-relay
mkdir -p "$APP/data"
cp "$HERE/index.ts" "$HERE/package.json" "$HERE/bun.lock" "$APP/"
( cd "$APP" && /usr/local/bin/bun install --production )
chown -R hipno-relay:hipno-relay "$APP"

echo "[4/6] Installing systemd service"
cp "$HERE/hipno-relay.service" /etc/systemd/system/hipno-relay.service
systemctl daemon-reload
systemctl enable --now hipno-relay

echo "[5/6] Configuring Caddy (TLS for $DOMAIN)"
sed "s/relay\.hypnotype\.mangocloud\.cyou/$DOMAIN/" "$HERE/Caddyfile" > /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp
fi

echo "[6/6] Checking"
sleep 3
curl -fsS http://127.0.0.1:3005/healthz && echo
echo
echo "Relay service is running. Now make sure DNS has:  A  relay  ->  this server's IPv4  (DNS only)"
echo "Then test:  curl -i https://$DOMAIN/healthz"
