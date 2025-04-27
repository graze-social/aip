#!/bin/sh
set -e  # Exit immediately if a command exits with a non-zero status

# Run init script
/app/init.sh

# Start the AIP server
echo "Starting AIP server..."
exec pdm run aipserver
