#!/bin/sh
set -e

if [ ! -f /app/cert.pem ]; then
    openssl req -x509 -newkey rsa:4096 \
        -keyout /app/key.pem \
        -out /app/cert.pem \
        -days 365 \
        -nodes \
        -subj "/CN=localhost"
fi

python -c "from cryptography.fernet import Fernet; Fernet('$VAULT_ENCRYPTION_KEY')"

exec gunicorn \
    --certfile=/app/cert.pem \
    --keyfile=/app/key.pem \
    -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    -b 0.0.0.0:5000 \
    -w 1 \
    app:app
