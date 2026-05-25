#!/bin/bash
echo "PANIC BUTTON - Wipe all Hyperion data"
echo "Type 'WIPE' to confirm:"
read CONFIRM
if [ "$CONFIRM" = "WIPE" ]; then
    rm -rf ~/.hyperion
    echo "All Hyperion data wiped from disk"
else
    echo "Cancelled"
fi