from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import encrypt_value, decrypt_value
import json

db = SQLAlchemy()

def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    is_active_user = db.Column(db.Boolean, default=True)

    hosts = db.relationship('Host', backref='owner', lazy=True, cascade='all, delete-orphan')
    terminal_style = db.relationship('TerminalStyle', backref='owner', uselist=False, lazy=True, cascade='all, delete-orphan')
    snippets = db.relationship('CommandSnippet', backref='owner', lazy=True, cascade='all, delete-orphan')
    ai_config = db.relationship('AIConfig', backref='owner', uselist=False, lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('SessionRecording', backref='owner', lazy=True, cascade='all, delete-orphan')
    ssh_keys = db.relationship('SSHKeyPair', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt', salt_length=32)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_user


class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(120), nullable=False)
    auth_type = db.Column(db.String(20), default='password')
    _encrypted_password = db.Column('encrypted_password', db.Text, default='')
    _encrypted_ssh_key = db.Column('encrypted_ssh_key', db.Text, default='')
    _encrypted_passphrase = db.Column('encrypted_passphrase', db.Text, default='')
    description = db.Column(db.Text, default='')
    is_favorite = db.Column(db.Boolean, default=False)
    color_tag = db.Column(db.String(20), default='')
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    recordings = db.relationship('SessionRecording', backref='host', lazy=True, cascade='all, delete-orphan')

    @property
    def password(self):
        return decrypt_value(self._encrypted_password) if self._encrypted_password else ''

    @password.setter
    def password(self, value):
        self._encrypted_password = encrypt_value(value) if value else ''

    @property
    def ssh_key(self):
        return decrypt_value(self._encrypted_ssh_key) if self._encrypted_ssh_key else ''

    @ssh_key.setter
    def ssh_key(self, value):
        self._encrypted_ssh_key = encrypt_value(value) if value else ''

    @property
    def passphrase(self):
        return decrypt_value(self._encrypted_passphrase) if self._encrypted_passphrase else ''

    @passphrase.setter
    def passphrase(self, value):
        self._encrypted_passphrase = encrypt_value(value) if value else ''


class TerminalStyle(db.Model):
    __tablename__ = 'terminal_styles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    name = db.Column(db.String(80), default='Custom')
    background = db.Column(db.String(7), default='#1c1c1c')
    foreground = db.Column(db.String(7), default='#ededed')
    cursor_color = db.Column(db.String(7), default='#3ecf8e')
    selection_bg = db.Column(db.String(9), default='#3ecf8e4d')
    color_black = db.Column(db.String(7), default='#1c1c1c')
    color_red = db.Column(db.String(7), default='#f56565')
    color_green = db.Column(db.String(7), default='#3ecf8e')
    color_yellow = db.Column(db.String(7), default='#ecc94b')
    color_blue = db.Column(db.String(7), default='#63b3ed')
    color_magenta = db.Column(db.String(7), default='#b794f6')
    color_cyan = db.Column(db.String(7), default='#76e4f7')
    color_white = db.Column(db.String(7), default='#ededed')
    font_size = db.Column(db.Integer, default=14)
    font_family = db.Column(db.String(200), default="'JetBrains Mono', monospace")
    cursor_blink = db.Column(db.Boolean, default=True)
    cursor_style = db.Column(db.String(20), default='block')
    bg_image_url = db.Column(db.Text, default='')
    bg_opacity = db.Column(db.Float, default=1.0)
    bg_blur = db.Column(db.Integer, default=0)
    scrollback = db.Column(db.Integer, default=10000)

    def to_xterm_theme(self):
        return {
            'background': self.background, 'foreground': self.foreground,
            'cursor': self.cursor_color, 'cursorAccent': self.background,
            'selectionBackground': self.selection_bg,
            'black': self.color_black, 'red': self.color_red,
            'green': self.color_green, 'yellow': self.color_yellow,
            'blue': self.color_blue, 'magenta': self.color_magenta,
            'cyan': self.color_cyan, 'white': self.color_white,
            'brightBlack': '#666666', 'brightRed': '#fc8181',
            'brightGreen': '#68d391', 'brightYellow': '#fbd38d',
            'brightBlue': '#90cdf4', 'brightMagenta': '#d6bcfa',
            'brightCyan': '#9decf9', 'brightWhite': '#ffffff'
        }

    def to_dict(self):
        return {
            'theme': self.to_xterm_theme(), 'fontSize': self.font_size,
            'fontFamily': self.font_family, 'cursorBlink': self.cursor_blink,
            'cursorStyle': self.cursor_style, 'scrollback': self.scrollback,
            'bgImageUrl': self.bg_image_url or '', 'bgOpacity': self.bg_opacity,
            'bgBlur': self.bg_blur
        }


class CommandSnippet(db.Model):
    __tablename__ = 'command_snippets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(80), default='Allgemein')
    title = db.Column(db.String(200), nullable=False)
    command = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, default='')
    is_global = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class AIConfig(db.Model):
    __tablename__ = 'ai_configs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    provider = db.Column(db.String(20), default='ollama')
    model = db.Column(db.String(100), default='llama3')
    _encrypted_api_key = db.Column('encrypted_api_key', db.Text, default='')
    ollama_url = db.Column(db.String(500), default='http://localhost:11434')
    system_prompt = db.Column(db.Text, default='You are a helpful Linux/SSH expert. '
                              'Respond precisely with commands and brief explanations. '
                              'Format commands in ```bash code blocks.')
    ai_enabled = db.Column(db.Boolean, default=True)
    doc_prompt = db.Column(db.Text, default='')

    @property
    def api_key(self):
        return decrypt_value(self._encrypted_api_key) if self._encrypted_api_key else ''

    @api_key.setter
    def api_key(self, value):
        self._encrypted_api_key = encrypt_value(value) if value else ''


class SessionRecording(db.Model):
    __tablename__ = 'session_recordings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    started_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    ended_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, default=0)
    commands_json = db.Column(db.Text, default='[]')
    output_log = db.Column(db.Text, default='')
    input_log = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='active')

    @property
    def commands(self):
        try:
            return json.loads(self.commands_json) if self.commands_json else []
        except (json.JSONDecodeError, TypeError):
            return []

    @commands.setter
    def commands(self, value):
        self.commands_json = json.dumps(value, ensure_ascii=False)

    def add_command(self, cmd, timestamp=None):
        cmds = self.commands
        cmds.append({'cmd': cmd, 'ts': (timestamp or utcnow()).isoformat(), 'idx': len(cmds)})
        self.commands = cmds

    def get_summary(self):
        cmds = self.commands
        return {
            'id': self.id, 'host_id': self.host_id,
            'host_name': self.host.name if self.host else 'Unbekannt',
            'started_at': self.started_at.isoformat() if self.started_at else '',
            'ended_at': self.ended_at.isoformat() if self.ended_at else '',
            'duration': self.duration_seconds, 'status': self.status,
            'command_count': len(cmds), 'commands': cmds[-50:],
        }

    def get_full_log(self):
        return {
            'id': self.id, 'host_name': self.host.name if self.host else 'Unbekannt',
            'started_at': self.started_at.isoformat() if self.started_at else '',
            'ended_at': self.ended_at.isoformat() if self.ended_at else '',
            'duration': self.duration_seconds, 'commands': self.commands,
            'output_log': self.output_log or '', 'input_log': self.input_log or '',
            'status': self.status
        }


class SSHKeyPair(db.Model):
    __tablename__ = 'ssh_key_pairs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    key_type = db.Column(db.String(20), default='ed25519')
    bits = db.Column(db.Integer, default=0)
    _encrypted_private_key = db.Column('encrypted_private_key', db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String(200), default='')
    _encrypted_passphrase = db.Column('encrypted_passphrase', db.Text, default='')
    deployed_hosts = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=utcnow)

    @property
    def private_key(self):
        return decrypt_value(self._encrypted_private_key) if self._encrypted_private_key else ''

    @private_key.setter
    def private_key(self, value):
        self._encrypted_private_key = encrypt_value(value) if value else ''

    @property
    def passphrase(self):
        return decrypt_value(self._encrypted_passphrase) if self._encrypted_passphrase else ''

    @passphrase.setter
    def passphrase(self, value):
        self._encrypted_passphrase = encrypt_value(value) if value else ''

    @property
    def deployed_host_ids(self):
        try:
            return json.loads(self.deployed_hosts) if self.deployed_hosts else []
        except (json.JSONDecodeError, TypeError):
            return []

    @deployed_host_ids.setter
    def deployed_host_ids(self, value):
        self.deployed_hosts = json.dumps(value)

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'key_type': self.key_type,
            'bits': self.bits, 'public_key': self.public_key,
            'fingerprint': self.fingerprint,
            'deployed_hosts': self.deployed_host_ids,
            'created_at': self.created_at.isoformat() if self.created_at else ''
        }

class WikiPage(db.Model):
    __tablename__ = 'wiki_pages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False, default='Ohne Titel')
    content = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)