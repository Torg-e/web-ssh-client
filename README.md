# Teashell Web-ssh-client
A modern-looking web SSH client focused on session recordings and built-in AI that compiles sessions into compact documentation. includes a wiki with a markdown editor to quickly create notes and documents, which can later be exported as Markdown and added to your documentation tools.

# Some Preview Pictures

### Login
<img width="1894" height="882" alt="Image" src="https://github.com/user-attachments/assets/eeee44e3-1f4f-4053-810e-b72314814b78" />


### Dashboard
<img width="1890" height="887" alt="image" src="https://github.com/user-attachments/assets/01289645-8d11-406d-afd3-adf2136a81fc" />


### Styles
<img width="1884" height="876" alt="image" src="https://github.com/user-attachments/assets/69994ed3-988f-452a-a708-4bbf5b374b03" />


### Ai Settings
<img width="1182" height="832" alt="image" src="https://github.com/user-attachments/assets/f12c3242-83f2-4b46-be99-3afe3e0a6cbf" />



# TeaShell Docker Quickstart

## Requirements

Docker Engine 20.10+ and Docker Compose plugin.

## 1. Environment

Create `.env` in the project root. Generate secrets before first start:

```bash
openssl rand -hex 32
openssl rand -base64 32 | tr '+/' '-_'
```

Minimal example:

```bash
##############################################
# Security & Secrets
##############################################
SECRET_KEY=super-secure-secret-at-least-32-characters
DATABASE_URL=sqlite:////app/data/ssh_vault.db

# To get an valid Vault Encryption Key use: 
# openssl rand -base64 32 | tr '+/' '-_'
VAULT_ENCRYPTION_KEY=EXAMPLEERJPocTS0OKV85wD5aapkTioO47q5p8ZAF7s=

##############################################
# Session & Cookie Security
##############################################
SESSION_COOKIE_SECURE=false
REMEMBER_COOKIE_SECURE=false
WTF_CSRF_SSL_STRICT=false

##############################################
# Network & Proxy
##############################################
TRUSTED_PROXIES_COUNT=1
CORS_ALLOWED_ORIGINS=*
TRUSTED_PROXY_IPS=192.168.1.19

##############################################
# Application
##############################################
EXTERNAL_PORT=5000
FLASK_ENV=production

##############################################
# SocketIO
##############################################
SOCKETIO_PING_TIMEOUT=120
SOCKETIO_PING_INTERVAL=25

##############################################
# Terminal Defaults
##############################################
TERMINAL_COLS=120
TERMINAL_ROWS=40

##############################################
# SSH
##############################################
SSH_KEEPALIVE=30

##############################################
# AI Integration
##############################################
OLLAMA_BASE_URL=http://ollama:11434
AI_ENABLED=true

##############################################
# Rate Limiting
##############################################
LOGIN_MAX_ATTEMPTS=5
LOGIN_RATE_LIMIT=300

##############################################
# Log Limits
##############################################
MAX_OUTPUT_LOG=500000
MAX_INPUT_LOG=100000

```

No quotes around `CORS_ALLOWED_ORIGINS`. Protocol is mandatory.

## 2. docker-compose.yml

```yaml
services:
  teashell:
    image: ghcr.io/torg-e/teashell:latest
    container_name: teashell
    env_file: .env
    ports:
      - "${EXTERNAL_PORT:-5000}:5000"
    networks:
      - teashell
    restart: unless-stopped
    volumes:
      - teashell-data:/app/data

networks:
  teashell:
    driver: bridge

volumes:
  teashell-data:

```

## 3. Start

```bash
docker compose up -d
```

Database and SSH vault are persisted in the named volume `teashell-data`.

## 4. First Login

Open `https://host:5000` in a browser. The first registered account receives admin privileges.

## 5. Reverse Proxy

If terminating TLS at Nginx, Traefik or any other reverse proxy:

- Set `TRUSTED_PROXIES_COUNT=1`, `SESSION_COOKIE_SECURE=true`, `REMEMBER_COOKIE_SECURE=true`, `WTF_CSRF_SSL_STRICT=true`
- Add the proxy IP to `TRUSTED_PROXY_IPS`
- Forward WebSocket Upgrade headers (not needed but recommended):

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```
