#!/bin/bash
echo "Removing Hyperion Docker images..."
docker rmi hyperion:latest 2>/dev/null
echo "Cleaned!"