#!/bin/bash
read -p "Enter peer address: " addr
docker run -it --rm -v ~/.hyperion:/root/.hyperion hyperion:latest connect $addr