#!/bin/bash
echo "[*] Starting Tor daemon..."
tor --ControlPort 9051 --SOCKSPort 9050 --RunAsDaemon 1

echo "[*] Waiting for Tor to be ready..."
for i in $(seq 1 30); do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',9050)); s.close()" 2>/dev/null; then
        echo "[+] Tor is ready (${i}s)"
        break
    fi
    echo "    waiting... ($i/30)"
    sleep 1
done

exec python3 /hyperion/main.py "$@"