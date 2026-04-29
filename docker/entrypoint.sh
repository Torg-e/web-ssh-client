#!/bin/sh
set -e

python -c "from cryptography.fernet import Fernet; Fernet('$VAULT_ENCRYPTION_KEY')"

exec gunicorn \
    -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    -b 0.0.0.0:5000 \
    -w 1 \
    app:app
