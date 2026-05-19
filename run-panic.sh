#!/bin/bash
read -p "Type WIPE to delete all data: " confirm
[ "$confirm" = "WIPE" ] && rm -rf ~/.hyperion && echo "Done"