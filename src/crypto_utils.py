import os
import base64
from cryptography.fernet import Fernet

_fernet_instance = None


def _get_fernet(app=None):
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance

    from flask import current_app
    config_src = app or current_app

    key = config_src.config.get('VAULT_ENCRYPTION_KEY')

    if not key:
        key_file = os.path.join(
            config_src.config.get('BASE_DIR', os.path.abspath(os.path.dirname(__file__))),
            '.vault_key'
        )
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read().decode()
        else:
            key = Fernet.generate_key().decode()
            with open(key_file, 'wb') as f:
                f.write(key.encode())
            os.chmod(key_file, 0o600)

    _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet_instance


def init_crypto(app):
    global _fernet_instance
    _fernet_instance = None
    with app.app_context():
        _get_fernet(app)


def encrypt_value(plaintext: str) -> str:
    if not plaintext:
        return ""
    f = _get_fernet()
    encrypted = f.encrypt(plaintext.encode('utf-8'))
    return base64.urlsafe_b64encode(encrypted).decode('utf-8')


def decrypt_value(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    f = _get_fernet()
    encrypted = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
    return f.decrypt(encrypted).decode('utf-8')