#!/bin/bash
echo "Starting Hyperion in HOST mode..."
echo ""
docker run -it \
  --rm \
  --name hyperion-host \
  -p 9999:9999 \
  -v ~/.hyperion:/root/.hyperion \
  hyperion:latest host