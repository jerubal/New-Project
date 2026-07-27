#!/bin/sh
set -e

TOKEN_DIR="/var/lib/softhsm/tokens"

# Initialize SoftHSM token if no tokens exist
if [ -z "$(ls -A $TOKEN_DIR)" ]; then
    if [ -z "$HSM_PIN" ] || [ -z "$HSM_SO_PIN" ]; then
        echo "ERROR: HSM_PIN and HSM_SO_PIN environment variables must be explicitly set!"
        exit 1
    fi
    echo "Initializing SoftHSM token..."
    softhsm2-util --init-token --slot 0 --label "issuingca" --pin "$HSM_PIN" --so-pin "$HSM_SO_PIN"
else
    echo "SoftHSM token already initialized."
fi

# Execute the main container command
exec "$@"
