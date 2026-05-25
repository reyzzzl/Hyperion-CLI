#!/bin/bash
echo "Enter peer address (e.g., localhost:9999 or xyz.onion):"
read PEER_ADDR
echo ""
echo "Connecting to $PEER_ADDR..."
docker run -it \
  --rm \
  -v ~/.hyperion:/root/.hyperion \
  hyperion:latest connect $PEER_ADDR