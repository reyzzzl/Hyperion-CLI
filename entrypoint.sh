#!/bin/bash

echo "[*] Starting Tor daemon..."
tor --ControlPort 9051 --SOCKSPort 9050 --RunAsDaemon 1

sleep 5

echo "[*] Tor is running. Starting Hyperion..."
exec python3 /hyperion/main.py "$@"