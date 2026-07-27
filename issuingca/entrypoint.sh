#!/bin/sh
set -e

TOKEN_DIR="/var/lib/softhsm/tokens"

# Initialize SoftHSM token if no tokens exist
if [ -z "$(ls -A $TOKEN_DIR)" ]; then
    echo "Initializing SoftHSM token..."
    softhsm2-util --init-token --slot 0 --label "issuingca" --pin "${HSM_PIN:-1234}" --so-pin "${HSM_SO_PIN:-1234}"
else
    echo "SoftHSM token already initialized."
fi

# Execute the main container command
exec "$@"
