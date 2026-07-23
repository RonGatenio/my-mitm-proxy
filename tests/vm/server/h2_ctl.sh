#!/usr/bin/env bash
# Run ON C. `start`: install nghttpd if needed, stop the h1 tls-server, build the
# docroot (small files + a 30 MiB blob + its sha256), and serve HTTP/2 on :443
# with the pinned leaf. `stop`: stop nghttpd and restore tls-server. Idempotent.
set -u
DOC=/opt/tlssrv/htdocs
KEY=/opt/tlssrv/leaf.key
CRT=/opt/tlssrv/leaf.pem
case "${1:-}" in
  start)
    command -v nghttpd >/dev/null 2>&1 || {
      sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nghttp2-server
    }
    sudo systemctl stop tls-server 2>/dev/null || true
    sudo mkdir -p "$DOC"
    echo h2-ok | sudo tee "$DOC/probe.txt" >/dev/null
    for i in 1 2 3 4 5; do echo "body-$i" | sudo tee "$DOC/m$i" >/dev/null; done
    sudo head -c 31457280 /dev/urandom | sudo tee "$DOC/big.bin" >/dev/null   # 30 MiB
    sudo sha256sum "$DOC/big.bin" | cut -d' ' -f1 | sudo tee "$DOC/big.sha256" >/dev/null
    sudo systemctl reset-failed nghttpd 2>/dev/null || true
    sudo systemd-run --unit=nghttpd --collect "$(command -v nghttpd)" -d "$DOC" 443 "$KEY" "$CRT"
    sleep 1
    systemctl is-active nghttpd
    ;;
  stop)
    sudo systemctl stop nghttpd 2>/dev/null || true
    sudo systemctl reset-failed nghttpd 2>/dev/null || true
    sudo systemctl start tls-server 2>/dev/null || true
    ;;
  *) echo "usage: h2_ctl.sh {start|stop}"; exit 2;;
esac
