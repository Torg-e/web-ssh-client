import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(64)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'ssh_vault.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    VAULT_ENCRYPTION_KEY = os.environ.get('VAULT_ENCRYPTION_KEY')

    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    REMEMBER_COOKIE_HTTPONLY = os.environ.get('REMEMBER_COOKIE_HTTPONLY', 'true').lower() == 'true'
    REMEMBER_COOKIE_SECURE = os.environ.get('REMEMBER_COOKIE_SECURE', 'false').lower() == 'true'
    REMEMBER_COOKIE_DURATION = int(os.environ.get('REMEMBER_COOKIE_DURATION', 3600))

    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
    WTF_CSRF_SSL_STRICT = os.environ.get('WTF_CSRF_SSL_STRICT', 'false').lower() == 'true'

    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
    OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')

    AI_ENABLED = os.environ.get('AI_ENABLED', 'true').lower() == 'true'
    LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', 5))
    LOGIN_RATE_LIMIT = int(os.environ.get('LOGIN_RATE_LIMIT', 300))
    MAX_OUTPUT_LOG = int(os.environ.get('MAX_OUTPUT_LOG', 500_000))
    MAX_INPUT_LOG = int(os.environ.get('MAX_INPUT_LOG', 100_000))
    SSH_KEEPALIVE = int(os.environ.get('SSH_KEEPALIVE', 30))
    TERMINAL_COLS = int(os.environ.get('TERMINAL_COLS', 120))
    TERMINAL_ROWS = int(os.environ.get('TERMINAL_ROWS', 40))
    SOCKETIO_PING_TIMEOUT = int(os.environ.get('SOCKETIO_PING_TIMEOUT', 120))
    SOCKETIO_PING_INTERVAL = int(os.environ.get('SOCKETIO_PING_INTERVAL', 25))

    _TRUSTED_PROXIES_COUNT = os.environ.get('TRUSTED_PROXIES_COUNT', '0')
    TRUSTED_PROXIES_COUNT = int(_TRUSTED_PROXIES_COUNT) if _TRUSTED_PROXIES_COUNT.isdigit() else 0
    TRUSTED_PROXY_IPS = os.environ.get('TRUSTED_PROXY_IPS', '')

    _cors = os.environ.get('CORS_ALLOWED_ORIGINS', '')
    if _cors == '*':
        CORS_ALLOWED_ORIGINS = '*'
    elif _cors:
        CORS_ALLOWED_ORIGINS = [x.strip() for x in _cors.split(',') if x.strip()]
    else:
        CORS_ALLOWED_ORIGINS = []
