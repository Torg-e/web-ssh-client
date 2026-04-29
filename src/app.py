from gevent import monkey
monkey.patch_all(thread=False)

import io
import re
import json
import os
import secrets
import time
import paramiko
from datetime import datetime, timezone
from flask import (
    Flask, abort, flash, jsonify, redirect,
    render_template, request, send_file, session, url_for
)
from flask_login import (
    LoginManager, current_user, login_required,
    login_user, logout_user
)
from flask_socketio import SocketIO, disconnect, emit
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix
from ai_client import chat_with_ai
from config import Config
from crypto_utils import init_crypto
from forms import (
    AIConfigForm, HostForm, LoginForm,
    RegisterForm, SnippetForm, TerminalStyleForm
)
from models import (
    AIConfig, CommandSnippet, Host, SSHKeyPair,
    SessionRecording, TerminalStyle, User,
    WikiPage, db, utcnow
)
from sftp_utils import (
    delete_remote, download_file, list_directory,
    mkdir_remote, rename_remote, upload_file
)
from ssh_keygen import deploy_key_to_host, generate_key_pair, remove_key_from_host

######################################### APP KONFIGURATION UND INITIALISIERUNG ##################################################
##################################################################################################################################

app = Flask(__name__)
app.config.from_object(Config)

class IPBasedProxyFix:
    def __init__(self, app, trusted_ips, proxy_count=1):
        self.app = ProxyFix(
            app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
            x_port=proxy_count,
            x_prefix=proxy_count
        )
        self.trusted_ips = set(trusted_ips)

    def __call__(self, environ, start_response):
        remote_addr = environ.get('REMOTE_ADDR', '')
        if remote_addr not in self.trusted_ips:
            for key in list(environ.keys()):
                if key.startswith('HTTP_X_FORWARDED'):
                    del environ[key]
        return self.app(environ, start_response)

trusted_ips = [ip.strip() for ip in Config.TRUSTED_PROXY_IPS.split(',') if ip.strip()]
if trusted_ips and Config.TRUSTED_PROXIES_COUNT > 0:
    app.wsgi_app = IPBasedProxyFix(
        app.wsgi_app,
        trusted_ips,
        proxy_count=Config.TRUSTED_PROXIES_COUNT
    )

db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'
socketio = SocketIO(
    app, async_mode='gevent',
    cors_allowed_origins=Config.CORS_ALLOWED_ORIGINS,
    manage_session=False,
    ping_timeout=Config.SOCKETIO_PING_TIMEOUT,
    ping_interval=Config.SOCKETIO_PING_INTERVAL
)
init_crypto(app)

########################################## DATENBANK SETUP UND DEFAULTS ##########################################################
##################################################################################################################################

with app.app_context():
    db.create_all()
    stale = SessionRecording.query.filter_by(status='active').all()
    for s in stale:
        s.status = 'interrupted'
        s.ended_at = utcnow()
    if stale:
        db.session.commit()
    if CommandSnippet.query.count() == 0:
        defaults = [
            ('System', 'Disk Usage', 'df -h', 'Shows disk usage'),
            ('System', 'Memory Info', 'free -h', 'RAM usage'),
            ('System', 'CPU Info', 'lscpu', 'Show CPU details'),
            ('System', 'Uptime', 'uptime', 'System uptime'),
            ('System', 'Top Processes', 'top -bn1 | head -20', 'Top CPU processes'),
            ('System', 'Kernel Version', 'uname -a', 'Kernel and OS info'),
            ('Network', 'IP Addresses', 'ip addr show', 'All network interfaces'),
            ('Network', 'Open Ports', 'ss -tulpn', 'Listening ports'),
            ('Network', 'DNS Lookup', 'dig google.com', 'DNS query'),
            ('Network', 'Ping Test', 'ping -c 4 8.8.8.8', 'Ping Google DNS'),
            ('Network', 'Route Table', 'ip route show', 'Routing table'),
            ('Docker', 'Container List', 'docker ps -a', 'All containers'),
            ('Docker', 'Images', 'docker images', 'All Docker images'),
            ('Docker', 'Docker Stats', 'docker stats --no-stream', 'Container resources'),
            ('Docker', 'Docker Logs', 'docker logs --tail 50 ', 'Last 50 log lines'),
            ('Files', 'Directory Size', 'du -sh *', 'Size of all folders'),
            ('Files', 'Recent Changes', 'find . -mtime -1 -type f', 'Files changed today'),
            ('Services', 'Systemd Status', 'systemctl list-units --type=service --state=running', 'Running services'),
            ('Services', 'Journal Logs', 'journalctl -xe --no-pager | tail -30', 'Latest system logs'),
            ('Security', 'Login Attempts', 'lastb | head -20', 'Failed logins'),
            ('Security', 'Active Users', 'who', 'Logged in users'),
            ('Security', 'Firewall Status', 'ufw status verbose', 'UFW firewall rules'),
        ]
        for cat, title, cmd, desc in defaults:
            db.session.add(CommandSnippet(user_id=0, category=cat, title=title,
                                          command=cmd, description=desc, is_global=True))
        db.session.commit()

######################################### KONSTANTEN UND GLOBALE VARIABLEN #######################################################
##################################################################################################################################

ssh_sessions = {}
recording_to_sid = {}
_host_tokens = {}
_login_attempts = {}

MAX_OUTPUT_LOG = Config.MAX_OUTPUT_LOG
MAX_INPUT_LOG = Config.MAX_INPUT_LOG
LOGIN_MAX_ATTEMPTS = Config.LOGIN_MAX_ATTEMPTS
LOGIN_RATE_LIMIT = Config.LOGIN_RATE_LIMIT
SSH_KEEPALIVE = Config.SSH_KEEPALIVE
TERMINAL_COLS = Config.TERMINAL_COLS
TERMINAL_ROWS = Config.TERMINAL_ROWS

############################################## HILFSFUNKTIONEN ###################################################################
##################################################################################################################################

def _create_host_token(host_id, user_id):
    token = secrets.token_hex(32)
    key = f"{user_id}:{host_id}"
    if key not in _host_tokens:
        _host_tokens[key] = {'tokens': set(), 'user_id': user_id}
    tokens = _host_tokens[key]['tokens']
    if len(tokens) >= 5:
        tokens.pop()
    tokens.add(token)
    return token

def _validate_host_token(host_id, user_id, token):
    key = f"{user_id}:{host_id}"
    entry = _host_tokens.get(key)
    if not entry:
        return False
    return token in entry['tokens']

def _refresh_host_token(host_id, user_id, old_token):
    new_token = _create_host_token(host_id, user_id)
    return new_token

def registration_allowed():
    return User.query.count() == 0

def _calc_duration(start, end):
    if start is None or end is None:
        return 0
    if start.tzinfo is None and end.tzinfo is not None:
        start = start.replace(tzinfo=timezone.utc)
    elif start.tzinfo is not None and end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    try:
        return max(0, int((end - start).total_seconds()))
    except Exception:
        return 0

def _check_rate_limit(ip):
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < 300]
    _login_attempts[ip] = attempts
    return len(attempts) < 5

def _record_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

def _is_safe_url(target):
    from urllib.parse import urlparse
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('', 'http', 'https') and ref_url.netloc == test_url.netloc

######################################### MIDDLEWARE, CONTEXT PROCESSORS, USER LOADER ############################################
##################################################################################################################################

@app.after_request
def security_headers(response):
    if 'text/html' in response.content_type:
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.context_processor
def inject_globals():
    cfg = None
    if current_user.is_authenticated:
        cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
    return dict(csrf_token=generate_csrf, registration_open=registration_allowed(), ai_cfg=cfg)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

######################################### AUTHENTIFIZIERUNGS ROUTEN ##############################################################
##################################################################################################################################

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    ip = request.remote_addr
    if form.validate_on_submit():
        if not _check_rate_limit(ip):
            flash('Too many login attempts. Please wait 5 minutes.', 'danger')
            return render_template('login.html', form=form), 429
        _record_attempt(ip)
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            session.permanent = True
            session['_fresh_token'] = secrets.token_hex(16)
            next_page = request.args.get('next')
            if next_page and not _is_safe_url(next_page):
                next_page = None
            flash('Logged in!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if not registration_allowed():
        flash('Registration is disabled. Contact the administrator.', 'warning')
        return redirect(url_for('login'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html', form=form)
        user = User(username=form.username.data, is_admin=True)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        db.session.add(TerminalStyle(user_id=user.id, name='Default'))
        db.session.add(AIConfig(user_id=user.id))
        db.session.commit()
        flash('Admin account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

############################################## ADMIN ROUTEN ######################################################################
##################################################################################################################################

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.created_at).all()
    ai_cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
    return render_template('admin.html', users=users, ai_cfg=ai_cfg)

@app.route('/admin/user/create', methods=['POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin:
        abort(403)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    if not username or not password or len(password) < 12:
        flash('Username and password (min. 12 characters) required.', 'danger')
        return redirect(url_for('admin_panel'))
    if User.query.filter_by(username=username).first():
        flash('Username already taken.', 'danger')
        return redirect(url_for('admin_panel'))
    user = User(username=username, is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    db.session.add(TerminalStyle(user_id=user.id, name='Default'))
    db.session.add(AIConfig(user_id=user.id))
    db.session.commit()
    flash(f'Benutzer "{username}" created.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    if user_id == current_user.id:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('admin_panel'))
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    db.session.delete(user)
    db.session.commit()
    flash(f'Benutzer "{user.username}" deleted.', 'success')
    return redirect(url_for('admin_panel'))

########################################## SEITEN ROUTEN (HTML VIEWS) ############################################################
##################################################################################################################################

@app.route('/dashboard')
@login_required
def dashboard():
    favorites = Host.query.filter_by(user_id=current_user.id, is_favorite=True).order_by(Host.name).all()
    others = Host.query.filter_by(user_id=current_user.id, is_favorite=False).order_by(Host.name).all()
    recent_sessions = SessionRecording.query.filter_by(user_id=current_user.id) \
        .order_by(SessionRecording.started_at.desc()).limit(10).all()
    return render_template('dashboard.html', favorites=favorites, hosts=others,
                           recent_sessions=recent_sessions)

@app.route('/api/hosts', methods=['POST'])
@login_required
def api_create_host():
    data = request.get_json()
    if not data or not data.get('name') or not data.get('hostname') or not data.get('username'):
        return jsonify({'error': 'Name, Hostname and Username are required'}), 400
    host = Host(
        user_id=current_user.id,
        name=data['name'].strip(),
        hostname=data['hostname'].strip(),
        port=data.get('port', 22),
        username=data['username'].strip(),
        auth_type=data.get('auth_type', 'password'),
        description=data.get('description', ''),
        is_favorite=data.get('is_favorite', False),
        color_tag=data.get('color_tag', '')
    )
    if host.auth_type == 'password':
        host.password = data.get('password', '')
    else:
        host.ssh_key = data.get('ssh_key', '')
        host.passphrase = data.get('passphrase', '')
    db.session.add(host)
    db.session.commit()
    return jsonify({'success': True, 'host_id': host.id})

@app.route('/api/hosts/<int:host_id>', methods=['GET', 'PUT'])
@login_required
def api_host_detail(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    if request.method == 'GET':
        return jsonify({
            'id': host.id, 'name': host.name, 'hostname': host.hostname,
            'port': host.port, 'username': host.username,
            'auth_type': host.auth_type, 'description': host.description,
            'is_favorite': host.is_favorite, 'color_tag': host.color_tag
        })
    data = request.get_json()
    host.name = data.get('name', host.name).strip()
    host.hostname = data.get('hostname', host.hostname).strip()
    host.port = data.get('port', host.port)
    host.username = data.get('username', host.username).strip()
    host.auth_type = data.get('auth_type', host.auth_type)
    host.description = data.get('description', host.description)
    host.is_favorite = data.get('is_favorite', host.is_favorite)
    host.color_tag = data.get('color_tag', host.color_tag)
    if host.auth_type == 'password' and data.get('password'):
        host.password = data['password']
    elif host.auth_type == 'key' and data.get('ssh_key'):
        host.ssh_key = data['ssh_key']
        if data.get('passphrase'):
            host.passphrase = data['passphrase']
    db.session.commit()
    return jsonify({'success': True})

@app.route('/host/new')
@login_required
def host_new():
    return redirect(url_for('dashboard'))

@app.route('/host/<int:host_id>/edit')
@login_required
def host_edit_redirect(host_id):
    return redirect(url_for('dashboard'))

@app.route('/host/<int:host_id>/delete', methods=['POST'])
@login_required
def host_delete(host_id):
    host = db.session.get(Host, host_id)
    if not host:
        abort(404)
    if host.user_id != current_user.id:
        abort(403)
    name = host.name
    db.session.delete(host)
    db.session.commit()
    flash(f'Host "{name}" deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/host/<int:host_id>/toggle-favorite', methods=['POST'])
@login_required
def host_toggle_favorite(host_id):
    host = db.session.get(Host, host_id)
    if not host:
        abort(404)
    if host.user_id != current_user.id:
        abort(403)
    host.is_favorite = not host.is_favorite
    db.session.commit()
    return jsonify({'is_favorite': host.is_favorite})

@app.route('/styles', methods=['GET', 'POST'])
@login_required
def terminal_styles():
    style = TerminalStyle.query.filter_by(user_id=current_user.id).first()
    if not style:
        style = TerminalStyle(user_id=current_user.id, name='Default')
        db.session.add(style)
        db.session.commit()
    form = TerminalStyleForm(obj=style)
    if form.validate_on_submit():
        form.populate_obj(style)
        db.session.commit()
        flash('Terminal-Style saved!', 'success')
        return redirect(url_for('terminal_styles'))
    return render_template('terminal_styles.html', form=form, style=style)

@app.route('/terminal/<int:host_id>')
@login_required
def terminal(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    ws_token = _create_host_token(host_id, current_user.id)
    style = TerminalStyle.query.filter_by(user_id=current_user.id).first()
    style_config = style.to_dict() if style else {}
    past_sessions = SessionRecording.query.filter_by(
        user_id=current_user.id, host_id=host_id
    ).order_by(SessionRecording.started_at.desc()).limit(20).all()
    sessions_data = [s.get_summary() for s in past_sessions]
    return render_template('terminal.html', host=host, ws_token=ws_token,
                           style_config=json.dumps(style_config),
                           sessions_data=json.dumps(sessions_data))

@app.route('/files/<int:host_id>')
@login_required
def file_browser(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    return render_template('file_browser.html', host=host)

@app.route('/commands')
@login_required
def commands_page():
    return render_template('commands.html')

@app.route('/keys')
@login_required
def ssh_keys_page():
    keys = SSHKeyPair.query.filter_by(user_id=current_user.id).order_by(SSHKeyPair.created_at.desc()).all()
    hosts = Host.query.filter_by(user_id=current_user.id).order_by(Host.name).all()
    return render_template('ssh_keys.html', keys=keys, hosts=hosts)

@app.route('/sessions')
@login_required
def sessions_page():
    sessions = SessionRecording.query.filter_by(user_id=current_user.id) \
        .order_by(SessionRecording.started_at.desc()).limit(100).all()
    return render_template('sessions.html', sessions=sessions)

@app.route('/wiki')
@login_required
def wiki():
    pages = WikiPage.query.filter_by(user_id=current_user.id).order_by(WikiPage.updated_at.desc()).all()
    highlight_id = request.args.get('highlight', type=int)
    return render_template('wiki.html', pages=pages, highlight_id=highlight_id)

######################################### API ROUTEN - STYLE PRESETS #############################################################
##################################################################################################################################

@app.route('/api/styles/presets')
@login_required
def style_presets():
    presets = {
        'supabase': {'name': 'Classic Dark', 'background': '#1c1c1c', 'foreground': '#ededed', 'cursor_color': '#3ecf8e', 'color_black': '#1c1c1c', 'color_red': '#f56565', 'color_green': '#3ecf8e', 'color_yellow': '#ecc94b', 'color_blue': '#63b3ed', 'color_magenta': '#b794f6', 'color_cyan': '#76e4f7', 'color_white': '#ededed'},
        'dracula': {'name': 'Dracula', 'background': '#282a36', 'foreground': '#f8f8f2', 'cursor_color': '#f8f8f2', 'color_black': '#21222c', 'color_red': '#ff5555', 'color_green': '#50fa7b', 'color_yellow': '#f1fa8c', 'color_blue': '#bd93f9', 'color_magenta': '#ff79c6', 'color_cyan': '#8be9fd', 'color_white': '#f8f8f2'},
        'monokai': {'name': 'Monokai', 'background': '#272822', 'foreground': '#f8f8f2', 'cursor_color': '#f8f8f0', 'color_black': '#272822', 'color_red': '#f92672', 'color_green': '#a6e22e', 'color_yellow': '#f4bf75', 'color_blue': '#66d9ef', 'color_magenta': '#ae81ff', 'color_cyan': '#a1efe4', 'color_white': '#f8f8f2'},
        'nord': {'name': 'Nord', 'background': '#2e3440', 'foreground': '#d8dee9', 'cursor_color': '#d8dee9', 'color_black': '#3b4252', 'color_red': '#bf616a', 'color_green': '#a3be8c', 'color_yellow': '#ebcb8b', 'color_blue': '#81a1c1', 'color_magenta': '#b48ead', 'color_cyan': '#88c0d0', 'color_white': '#e5e9f0'},
        'cyberpunk': {'name': 'Cyberpunk', 'background': '#0a0a0f', 'foreground': '#0ff0fc', 'cursor_color': '#ff2a6d', 'color_black': '#0a0a0f', 'color_red': '#ff2a6d', 'color_green': '#05d9e8', 'color_yellow': '#f7f052', 'color_blue': '#7122fa', 'color_magenta': '#ff2a6d', 'color_cyan': '#05d9e8', 'color_white': '#d1f7ff'},
        'matrix': {'name': 'Matrix', 'background': '#0d0208', 'foreground': '#00ff41', 'cursor_color': '#00ff41', 'color_black': '#0d0208', 'color_red': '#ff0000', 'color_green': '#00ff41', 'color_yellow': '#ffff00', 'color_blue': '#008f11', 'color_magenta': '#00ff41', 'color_cyan': '#003b00', 'color_white': '#00ff41'},
        'solarized': {'name': 'Solarized Dark', 'background': '#002b36', 'foreground': '#839496', 'cursor_color': '#839496', 'color_black': '#073642', 'color_red': '#dc322f', 'color_green': '#859900', 'color_yellow': '#b58900', 'color_blue': '#268bd2', 'color_magenta': '#d33682', 'color_cyan': '#2aa198', 'color_white': '#eee8d5'},
    }
    return jsonify(presets)

######################################### API ROUTEN - COMMAND SNIPPETS ##########################################################
##################################################################################################################################

@app.route('/api/snippets', methods=['GET'])
@login_required
def get_snippets():
    user_snippets = CommandSnippet.query.filter_by(user_id=current_user.id).all()
    global_snippets = CommandSnippet.query.filter_by(is_global=True).all()
    result = {}
    for s in global_snippets + user_snippets:
        if s.category not in result:
            result[s.category] = []
        result[s.category].append({'id': s.id, 'title': s.title, 'command': s.command,
                                   'description': s.description, 'is_global': s.is_global})
    return jsonify(result)

@app.route('/api/snippets', methods=['POST'])
@login_required
def create_snippet():
    data = request.get_json()
    if not data or not data.get('title') or not data.get('command'):
        return jsonify({'error': 'Title and command are required'}), 400
    s = CommandSnippet(user_id=current_user.id, category=data.get('category', 'Generally'),
                       title=data['title'], command=data['command'], description=data.get('description', ''))
    db.session.add(s)
    db.session.commit()
    return jsonify({'id': s.id}), 201

@app.route('/api/snippets/<int:sid>', methods=['DELETE'])
@login_required
def delete_snippet(sid):
    s = db.session.get(CommandSnippet, sid)
    if not s:
        abort(404)
    if s.user_id != current_user.id and not (s.is_global and current_user.is_admin):
        abort(403)
    db.session.delete(s)
    db.session.commit()
    return jsonify({'message': 'Deleted'})

######################################### API ROUTEN - SESSION RECORDINGS ########################################################
##################################################################################################################################

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    host_id = request.args.get('host_id', type=int)
    query = SessionRecording.query.filter_by(user_id=current_user.id)
    if host_id:
        query = query.filter_by(host_id=host_id)
    sessions = query.order_by(SessionRecording.started_at.desc()).limit(50).all()
    return jsonify([s.get_summary() for s in sessions])

@app.route('/api/sessions/<int:sid>', methods=['GET'])
@login_required
def get_session_detail(sid):
    s = db.session.get(SessionRecording, sid)
    if not s or s.user_id != current_user.id:
        abort(404)
    return jsonify(s.get_full_log())

@app.route('/api/sessions/<int:sid>', methods=['DELETE'])
@login_required
def delete_session_api(sid):
    s = db.session.get(SessionRecording, sid)
    if not s or s.user_id != current_user.id:
        abort(404)
    db.session.delete(s)
    db.session.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/api/sessions/<int:sid>/replay', methods=['GET'])
@login_required
def get_session_replay(sid):
    s = db.session.get(SessionRecording, sid)
    if not s or s.user_id != current_user.id:
        abort(404)
    live_sid = recording_to_sid.get(sid)
    is_live = False
    if live_sid and live_sid in ssh_sessions:
        ch = ssh_sessions[live_sid].get('channel')
        if ch and not ch.closed:
            is_live = True
    output = s.output_log or ''
    if is_live and live_sid in ssh_sessions:
        output += ssh_sessions[live_sid].get('output_buffer', '')
    return jsonify({
        'recording_id': sid, 'host_id': s.host_id, 'output_log': output,
        'commands': s.commands, 'status': s.status, 'is_live': is_live,
        'started_at': s.started_at.isoformat() if s.started_at else ''
    })

@app.route('/api/sessions/<int:sid>/context', methods=['GET'])
@login_required
def get_session_context(sid):
    s = db.session.get(SessionRecording, sid)
    if not s or s.user_id != current_user.id:
        abort(404)
    cmds = s.commands
    cmd_text = '\n'.join([f"[{c.get('ts', '')}] $ {c.get('cmd', '')}" for c in cmds])
    output_text = s.output_log[:8000] if s.output_log else '(no output)'
    context = (
        f"=== SESSION LOG: {s.host.name if s.host else 'Unknown'} ===\n"
        f"Started: {s.started_at}\nEnded: {s.ended_at or 'Activ'}\nStatus: {s.status}\n\n"
        f"--- COMMANDS ({len(cmds)}) ---\n{cmd_text}\n\n"
        f"--- OUTPUT (shortened) ---\n{output_text}"
    )
    return jsonify({'context': context, 'session_id': sid,
                    'host_name': s.host.name if s.host else 'Unknown'})

@app.route('/api/sessions/active/<int:host_id>', methods=['GET'])
@login_required
def get_active_session(host_id):
    rec = SessionRecording.query.filter_by(
        user_id=current_user.id, host_id=host_id, status='active'
    ).order_by(SessionRecording.started_at.desc()).first()
    if not rec:
        recent = SessionRecording.query.filter_by(
            user_id=current_user.id, host_id=host_id
        ).filter(SessionRecording.status.in_(['completed', 'interrupted', 'reconnected'])) \
         .order_by(SessionRecording.started_at.desc()).first()
        if recent and recent.output_log:
            return jsonify({'has_active': False, 'has_replay': True, 'recording_id': recent.id})
        return jsonify({'has_active': False})
    live_sid = recording_to_sid.get(rec.id)
    is_live = False
    if live_sid and live_sid in ssh_sessions:
        ch = ssh_sessions[live_sid].get('channel')
        if ch and not ch.closed:
            is_live = True
    if not is_live:
        return jsonify({'has_active': False, 'has_replay': True, 'recording_id': rec.id})
    return jsonify({
        'has_active': True, 'recording_id': rec.id,
        'started_at': rec.started_at.isoformat() if rec.started_at else '',
        'command_count': len(rec.commands)
    })

@app.route('/api/sessions/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_sessions():
    data = request.get_json()
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'error': 'No IDs passed'}), 400
    for sid in ids:
        rec = db.session.get(SessionRecording, sid)
        if rec and rec.user_id == current_user.id:
            db.session.delete(rec)
    db.session.commit()
    return jsonify({'success': True, 'deleted_count': len(ids)})

@app.route('/api/sessions/<int:recording_id>/ai_export', methods=['POST'])
@login_required
def ai_export_session(recording_id):
    rec = db.session.get(SessionRecording, recording_id)
    if not rec or rec.user_id != current_user.id:
        abort(404)
    
    ai_conf = AIConfig.query.filter_by(user_id=current_user.id).first()
    if not ai_conf or not ai_conf.ai_enabled:
        return jsonify({'error': 'AI features are currently disabled.'}), 403
    if not ai_conf or not ai_conf.api_key:
        return jsonify({'error': 'AI API key not configured.'}), 400
    
    commands = rec.get_summary() if hasattr(rec, 'get_summary') else "No commands available"
    output = (rec.output_log or '')[:3000]
    
    doc_prompt_template = ai_conf.doc_prompt or "Commands:\n{commands}\n\nTerminal Output:\n{output}"
    doc_prompt = doc_prompt_template.replace('{commands}', commands).replace('{output}', output)
    
    try:
        doc_result = chat_with_ai(ai_conf, [{'role': 'user', 'content': doc_prompt}])
        md_text = ""
        if isinstance(doc_result, dict):
            md_text = doc_result.get('text') or doc_result.get('content') or doc_result.get('message') or doc_result.get('response') or str(doc_result)
        elif isinstance(doc_result, str):
            md_text = doc_result
        else:
            md_text = str(doc_result)
        
        title_prompt = f"Generate a short, concise title (max 5 words, no quotation marks) for this documentation:\n\n{md_text[:500]}"
        title_result = chat_with_ai(ai_conf, [{'role': 'user', 'content': title_prompt}])
        title_text = "New Documentation"
        if isinstance(title_result, dict):
            title_text = title_result.get('text') or title_result.get('content') or title_result.get('message') or str(title_result)
        elif isinstance(title_result, str):
            title_text = title_result
        
        new_page = WikiPage(
            user_id=current_user.id,
            title=title_text.strip().replace('"', '').replace("'", ""),
            content=md_text
        )
        db.session.add(new_page)
        db.session.commit()
        return jsonify({'success': True, 'page_id': new_page.id})
    except Exception as e:
        return jsonify({'error': f'AI error: {str(e)}'}), 500

######################################### API ROUTEN - AI KONFIGURATION UND CHAT #################################################
##################################################################################################################################

@app.route('/api/ai/config', methods=['GET'])
@login_required
def get_ai_config():
    cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
    if not cfg:
        return jsonify({'provider': 'ollama', 'model': 'llama3', 'configured': False, 'ai_enabled': True})
    return jsonify({
        'provider': cfg.provider, 'model': cfg.model,
        'ollama_url': cfg.ollama_url,
        'has_key': bool(cfg._encrypted_api_key),
        'system_prompt': cfg.system_prompt,
        'configured': True,
        'ai_enabled': cfg.ai_enabled
    })

@app.route('/api/ai/config', methods=['POST'])
@login_required
def save_ai_config():
    if not current_user.is_admin:
        return jsonify({'error': 'Only administrators can configure the AI.'}), 403
    data = request.get_json()
    users = User.query.all()
    for user in users:
        cfg = AIConfig.query.filter_by(user_id=user.id).first()
        if not cfg:
            cfg = AIConfig(user_id=user.id)
            db.session.add(cfg)
        if 'provider' in data:
            cfg.provider = data['provider']
        if 'model' in data:
            cfg.model = data['model']
        if 'ollama_url' in data:
            cfg.ollama_url = data['ollama_url']
        if 'ai_enabled' in data:
            cfg.ai_enabled = bool(data['ai_enabled'])
        if data.get('api_key'):
            cfg.api_key = data['api_key']
        if data.get('system_prompt') is not None:
            cfg.system_prompt = data['system_prompt']
    db.session.commit()
    return jsonify({'message': 'AI configuration saved'})

@app.route('/api/ai/chat', methods=['POST'])
@login_required
def ai_chat():
    data = request.get_json()
    if not data or not data.get('messages'):
        return jsonify({'error': 'Messages required'}), 400
    ai_cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
    if not ai_cfg or not ai_cfg.ai_enabled:
        return jsonify({'error': 'AI features are currently disabled.'}), 403
    messages = data.get('messages', [])
    recording_id = data.get('recording_id')
    if recording_id:
        rec = db.session.get(SessionRecording, recording_id)
        if rec and rec.user_id == current_user.id:
            cmd_text = '\n'.join([f"$ {c.get('cmd', '')}" for c in rec.commands[-10:]])
            output_text = (rec.output_log or '')[-2000:]
            context_str = (
                f"\n\n[CURRENT SESSION CONTEXT]\n"
                f"Host: {rec.host.name if rec.host else 'Unknown'}\n"
                f"Last commands:\n{cmd_text}\n\n"
                f"Latest output:\n{output_text}\n"
                f"[/CONTEXT]\n\n"
            )
            if messages and messages[-1]['role'] == 'user':
                messages[-1]['content'] = context_str + messages[-1]['content']
    result = chat_with_ai(ai_cfg, messages)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result)

@app.route('/api/ai/test', methods=['POST'])
@login_required
def test_ai_connection_route():
    if not current_user.is_admin:
        return jsonify({'error': 'Admins only'}), 403
    data = request.get_json()
    provider = data.get('provider', 'ollama')
    api_key = data.get('api_key', '')
    ollama_url = data.get('ollama_url', 'http://localhost:11434')
    model = data.get('model', '')
    if not api_key:
        cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
        if cfg:
            api_key = cfg.api_key
    from ai_client import test_ai_connection
    result = test_ai_connection(provider, api_key, ollama_url, model)
    return jsonify(result)

@app.route('/api/ai/ollama-models', methods=['POST'])
@login_required
def get_ollama_models():
    if not current_user.is_admin:
        return jsonify({'error': 'Admins only'}), 403
    data = request.get_json()
    ollama_url = data.get('ollama_url', 'http://localhost:11434')
    api_key = data.get('api_key', '')
    if not api_key:
        cfg = AIConfig.query.filter_by(user_id=current_user.id).first()
        if cfg:
            api_key = cfg.api_key
    from ai_client import list_ollama_models
    result = list_ollama_models(ollama_url, api_key=api_key or None)
    return jsonify(result)

########################################## API ROUTEN - SFTP DATEI OPERATIONEN ###################################################
##################################################################################################################################

@app.route('/api/sftp/<int:host_id>/ls')
@login_required
def sftp_list(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    path = request.args.get('path', '/')
    try:
        entries = list_directory(host, path)
        return jsonify({'path': path, 'entries': entries})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sftp/<int:host_id>/download')
@login_required
def sftp_download(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    remote_path = request.args.get('path', '')
    if not remote_path:
        return jsonify({'error': 'Path is missing'}), 400
    try:
        data, filename = download_file(host, remote_path)
        return send_file(
            io.BytesIO(data), as_attachment=True,
            download_name=filename, mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sftp/<int:host_id>/upload', methods=['POST'])
@login_required
def sftp_upload(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    remote_path = request.form.get('path', '/')
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No filename'}), 400
    try:
        file_data = f.read()
        full_path = upload_file(host, remote_path, file_data, f.filename)
        return jsonify({'message': f'File uploaded: {full_path}', 'path': full_path})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sftp/<int:host_id>/mkdir', methods=['POST'])
@login_required
def sftp_mkdir(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    data = request.get_json()
    path = data.get('path', '')
    if not path:
        return jsonify({'error': 'Path is missing'}), 400
    try:
        mkdir_remote(host, path)
        return jsonify({'message': f'Directory created: {path}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sftp/<int:host_id>/delete', methods=['POST'])
@login_required
def sftp_delete(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    data = request.get_json()
    path = data.get('path', '')
    is_dir = data.get('is_dir', False)
    if not path:
        return jsonify({'error': 'Path is missing'}), 400
    try:
        delete_remote(host, path, is_dir)
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sftp/<int:host_id>/rename', methods=['POST'])
@login_required
def sftp_rename(host_id):
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        abort(404)
    data = request.get_json()
    old = data.get('old_path', '')
    new = data.get('new_path', '')
    if not old or not new:
        return jsonify({'error': 'Paths are missing'}), 400
    try:
        rename_remote(host, old, new)
        return jsonify({'message': 'Renamed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

######################################### API ROUTEN - SSH KEYS ##################################################################
##################################################################################################################################

@app.route('/api/keys', methods=['POST'])
@login_required
def create_ssh_key():
    data = request.get_json()
    name = data.get('name', '').strip()
    key_type = data.get('key_type', 'ed25519')
    bits = data.get('bits', 4096)
    passphrase = data.get('passphrase', '') or None
    if not name:
        return jsonify({'error': 'Name required'}), 400
    if key_type not in ('rsa', 'ed25519', 'ecdsa'):
        return jsonify({'error': 'Invalid key type'}), 400
    try:
        priv, pub, fp, actual_bits = generate_key_pair(key_type, bits, passphrase)
        kp = SSHKeyPair(
            user_id=current_user.id, name=name, key_type=key_type,
            bits=actual_bits, public_key=pub, fingerprint=fp
        )
        kp.private_key = priv
        if passphrase:
            kp.passphrase = passphrase
        db.session.add(kp)
        db.session.commit()
        return jsonify(kp.to_dict()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_ssh_key(key_id):
    kp = db.session.get(SSHKeyPair, key_id)
    if not kp or kp.user_id != current_user.id:
        abort(404)
    db.session.delete(kp)
    db.session.commit()
    return jsonify({'message': 'Key deleted'})

@app.route('/api/keys/<int:key_id>/private')
@login_required
def download_private_key(key_id):
    kp = db.session.get(SSHKeyPair, key_id)
    if not kp or kp.user_id != current_user.id:
        abort(404)
    return send_file(
        io.BytesIO(kp.private_key.encode()),
        as_attachment=True,
        download_name=f'{kp.name}_{kp.key_type}',
        mimetype='text/plain'
    )

@app.route('/api/keys/<int:key_id>/deploy', methods=['POST'])
@login_required
def deploy_ssh_key(key_id):
    kp = db.session.get(SSHKeyPair, key_id)
    if not kp or kp.user_id != current_user.id:
        abort(404)
    data = request.get_json()
    host_id = data.get('host_id')
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        return jsonify({'error': 'Host not found'}), 404
    try:
        result = deploy_key_to_host(host, kp.public_key)
        deployed = kp.deployed_host_ids
        if host_id not in deployed:
            deployed.append(host_id)
            kp.deployed_host_ids = deployed
            db.session.commit()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke_ssh_key(key_id):
    kp = db.session.get(SSHKeyPair, key_id)
    if not kp or kp.user_id != current_user.id:
        abort(404)
    data = request.get_json()
    host_id = data.get('host_id')
    host = db.session.get(Host, host_id)
    if not host or host.user_id != current_user.id:
        return jsonify({'error': 'Host not found'}), 404
    try:
        result = remove_key_from_host(host, kp.public_key)
        deployed = kp.deployed_host_ids
        if host_id in deployed:
            deployed.remove(host_id)
            kp.deployed_host_ids = deployed
            db.session.commit()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

########################################## API ROUTEN - WIKI #####################################################################
##################################################################################################################################

@app.route('/api/wiki/save', methods=['POST'])
@login_required
def save_wiki_page():
    data = request.get_json()
    page_id = data.get('id')
    title = data.get('title', 'Without title')
    content = data.get('content', '')
    if page_id:
        page = db.session.get(WikiPage, page_id)
        if not page or page.user_id != current_user.id:
            abort(404)
        page.title = title
        page.content = content
    else:
        page = WikiPage(user_id=current_user.id, title=title, content=content)
        db.session.add(page)
    db.session.commit()
    return jsonify({'success': True, 'id': page.id})

@app.route('/api/wiki/<int:page_id>', methods=['GET'])
@login_required
def get_wiki_page(page_id):
    page = db.session.get(WikiPage, page_id)
    if not page or page.user_id != current_user.id:
        abort(404)
    return jsonify({'id': page.id, 'title': page.title, 'content': page.content})

@app.route('/api/wiki/<int:page_id>/download')
@login_required
def download_wiki_page(page_id):
    page = db.session.get(WikiPage, page_id)
    if not page or page.user_id != current_user.id:
        abort(404)
    safe_title = "".join([c if c.isalnum() or c in (' ', '-', '_') else '_' for c in page.title]).rstrip()
    return send_file(
        io.BytesIO(page.content.encode('utf-8')),
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f"{safe_title}.md"
    )

@app.route('/api/wiki/<int:page_id>', methods=['DELETE'])
@login_required
def delete_wiki_page(page_id):
    page = db.session.get(WikiPage, page_id)
    if not page or page.user_id != current_user.id:
        abort(404)
    db.session.delete(page)
    db.session.commit()
    return jsonify({'success': True})

######################################### SSH VERBINDUNGS HILFSFUNKTIONEN ########################################################
##################################################################################################################################

def _create_ssh_connection(hostname, port, username, auth_type, password, ssh_key, passphrase, cols, rows):
    transport = paramiko.Transport((hostname, port))
    transport.set_keepalive(30)
    if auth_type == 'password':
        transport.connect(username=username, password=password)
    else:
        pkey = None
        pp = passphrase or None
        for kc in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
            try:
                pkey = kc.from_private_key(io.StringIO(ssh_key), password=pp)
                break
            except Exception:
                continue
        if pkey is None:
            raise ValueError("SSH key invalid")
        transport.connect(username=username, pkey=pkey)
    channel = transport.open_session()
    channel.get_pty(term='xterm-256color', width=cols, height=rows)
    channel.invoke_shell()
    return transport, channel

def _start_reader_thread(sid, channel):
    def read_output():
        try:
            while not channel.closed:
                if channel.recv_ready():
                    out = channel.recv(4096).decode('utf-8', errors='replace')
                    socketio.emit('output', {'data': out}, namespace='/ssh', to=sid)
                    sess = ssh_sessions.get(sid)
                    if sess and sess['output_size'] < MAX_OUTPUT_LOG:
                        sess['output_buffer'] += out
                        sess['output_size'] += len(out)
                        if time.time() - sess['last_flush'] > 10:
                            _flush_recording(sid)
                else:
                    socketio.sleep(0.05)
        except Exception as e:
            socketio.emit('output', {'data': f'\r\n\x1b[1;31m[SSH Error: {e}]\x1b[0m\r\n'},
                          namespace='/ssh', to=sid)
        finally:
            socketio.emit('output', {'data': '\r\n\x1b[1;33m[Connection terminated]\x1b[0m\r\n'},
                          namespace='/ssh', to=sid)
            socketio.emit('session_ended', {}, namespace='/ssh', to=sid)
            _finalize_session(sid)
    return socketio.start_background_task(read_output)

def _flush_recording(sid):
    sess = ssh_sessions.get(sid)
    if not sess or not sess.get('output_buffer'):
        return
    buf = sess['output_buffer']
    sess['output_buffer'] = ''
    sess['last_flush'] = time.time()
    with app.app_context():
        try:
            rec = db.session.get(SessionRecording, sess['recording_id'])
            if rec:
                rec.output_log = (rec.output_log or '') + buf; db.session.commit()
        except Exception:
            db.session.rollback()

def _finalize_session(sid):
    sess = ssh_sessions.pop(sid, None)
    if not sess:
        return
    rec_id = sess.get('recording_id')
    if rec_id and recording_to_sid.get(rec_id) == sid:
        del recording_to_sid[rec_id]
    with app.app_context():
        try:
            rec = db.session.get(SessionRecording, rec_id)
            if rec:
                if sess.get('output_buffer'):
                    rec.output_log = (rec.output_log or '') + sess['output_buffer']
                cmd = sess.get('cmd_buffer', '').strip()
                if cmd:
                    rec.add_command(cmd)
                rec.ended_at = utcnow()
                if rec.started_at:
                    rec.duration_seconds = _calc_duration(rec.started_at, rec.ended_at)
                rec.status = 'completed'
                db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
    try:
        ch = sess.get('channel')
        if ch: ch.close()
    except Exception:
        pass
    try:
        tr = sess.get('transport')
        if tr: tr.close()
    except Exception:
        pass

######################################### SOCKETIO EVENTS (SSH WEBSOCKET) ########################################################
##################################################################################################################################

@socketio.on('connect', namespace='/ssh')
def ssh_connect():
    if not current_user.is_authenticated:
        disconnect()
        return False

@socketio.on('start_session', namespace='/ssh')
def ssh_start(data):
    if not current_user.is_authenticated:
        disconnect()
        return
    host_id = data.get('host_id')
    ws_token = data.get('ws_token')
    reconnect_recording_id = data.get('reconnect_recording_id')
    sid = request.sid
    user_id = current_user.id
    cols = data.get('cols', 120)
    rows = data.get('rows', 40)
    if not _validate_host_token(host_id, user_id, ws_token):
        emit('output', {'data': '\r\n\x1b[1;31m[ERROR] Invalid token. Please reload the page.\x1b[0m\r\n'})
        disconnect()
        return
    new_token = _refresh_host_token(host_id, user_id, ws_token)
    emit('new_token', {'token': new_token})
    if reconnect_recording_id:
        live_sid = recording_to_sid.get(reconnect_recording_id)
        if live_sid and live_sid in ssh_sessions:
            old_sess = ssh_sessions[live_sid]
            ch = old_sess.get('channel')
            if ch and not ch.closed:
                _flush_recording(live_sid)
                ssh_sessions[sid] = old_sess
                del ssh_sessions[live_sid]
                recording_to_sid[reconnect_recording_id] = sid
                emit('output', {'data': '\r\n\x1b[1;32m✓ Live session restored\x1b[0m\r\n\r\n'})
                emit('recording_started', {'recording_id': reconnect_recording_id})
                try:
                    ch.resize_pty(width=cols, height=rows)
                except Exception:
                    pass
                old_sess['thread'] = _start_reader_thread(sid, ch)
                return
        emit('output', {'data': '\r\n\x1b[1;33m[Live session no longer available, restoring history...]\x1b[0m\r\n'})
    with app.app_context():
        host = db.session.get(Host, host_id)
        if not host or host.user_id != user_id:
            emit('output', {'data': '\r\n\x1b[1;31m[ERROR] Host not found.\x1b[0m\r\n'})
            disconnect()
            return
        h_hostname, h_port = host.hostname, host.port
        h_username, h_auth = host.username, host.auth_type
        h_pass, h_key, h_pp = host.password, host.ssh_key, host.passphrase
        h_name = host.name
        replay_output = None
        old_commands = []
        if reconnect_recording_id:
            old_rec = db.session.get(SessionRecording, reconnect_recording_id)
            if old_rec and old_rec.user_id == user_id:
                replay_output = old_rec.output_log or ''
                old_commands = old_rec.commands
                if old_rec.status == 'active':
                    old_rec.status = 'reconnected'
                    old_rec.ended_at = utcnow()
                    if old_rec.started_at:
                        old_rec.duration_seconds = _calc_duration(old_rec.started_at, old_rec.ended_at)
                    db.session.commit()
        recording = SessionRecording(user_id=user_id, host_id=host_id, started_at=utcnow(), status='active')
        if old_commands:
            recording.commands = old_commands
        db.session.add(recording)
        db.session.commit()
        recording_id = recording.id
    if replay_output:
        emit('replay_start', {})
        chunk_size = 8192
        for i in range(0, len(replay_output), chunk_size):
            emit('output', {'data': replay_output[i:i + chunk_size]})
            socketio.sleep(0)
        emit('replay_end', {})
        emit('output', {'data': '\r\n\x1b[1;36m--- History restored, new connection ---\x1b[0m\r\n\r\n'})
    try:
        transport, channel = _create_ssh_connection(
            h_hostname, h_port, h_username, h_auth, h_pass, h_key, h_pp, cols, rows)
        ssh_sessions[sid] = {
            'channel': channel, 'transport': transport,
            'recording_id': recording_id, 'user_id': user_id, 'host_id': host_id,
            'cmd_buffer': '', 'output_buffer': '',
            'output_size': 0, 'input_size': 0, 'last_flush': time.time()
        }
        recording_to_sid[recording_id] = sid
        emit('output', {'data': f'\r\n\x1b[1;32m✓ Connected to {h_name} ({h_hostname})\x1b[0m\r\n\r\n'})
        emit('recording_started', {'recording_id': recording_id})
        ssh_sessions[sid]['thread'] = _start_reader_thread(sid, channel)
    except paramiko.AuthenticationException as e:
        emit('output', {'data': '\r\n\x1b[1;31m[ERROR] Authentication failed.\x1b[0m\r\n'})
        with app.app_context():
            rec = db.session.get(SessionRecording, recording_id)
            if rec:
                rec.status = 'error'; rec.ended_at = utcnow(); db.session.commit()
    except Exception as e:
        emit('output', {'data': f'\r\n\x1b[1;31m[ERROR] {e}\x1b[0m\r\n'})
        with app.app_context():
            rec = db.session.get(SessionRecording, recording_id)
            if rec:
                rec.status = 'error'; rec.ended_at = utcnow(); db.session.commit()

@socketio.on('input', namespace='/ssh')
def ssh_input(data):
    sid = request.sid
    sess = ssh_sessions.get(sid)
    if not sess or not sess.get('channel') or sess['channel'].closed:
        return
    input_data = data.get('data', '')
    try:
        sess['channel'].send(input_data)
    except Exception:
        return
    if sess['input_size'] < MAX_INPUT_LOG:
        for char in input_data:
            if char in ('\r', '\n'):
                cmd = sess['cmd_buffer'].strip()
                if cmd:
                    with app.app_context():
                        try:
                            rec = db.session.get(SessionRecording, sess['recording_id'])
                            if rec:
                                rec.add_command(cmd); db.session.commit()
                        except Exception:
                            db.session.rollback()
                sess['cmd_buffer'] = ''
            elif char in ('\x7f', '\x08'):
                sess['cmd_buffer'] = sess['cmd_buffer'][:-1]
            elif char == '\x03':
                cmd = sess['cmd_buffer'].strip()
                if cmd:
                    with app.app_context():
                        try:
                            rec = db.session.get(SessionRecording, sess['recording_id'])
                            if rec:
                                rec.add_command(f'{cmd} [Ctrl+C]'); db.session.commit()
                        except Exception:
                            db.session.rollback()
                sess['cmd_buffer'] = ''
            elif ord(char) >= 32:
                sess['cmd_buffer'] += char; sess['input_size'] += 1

@socketio.on('resize', namespace='/ssh')
def ssh_resize(data):
    sess = ssh_sessions.get(request.sid)
    if sess and sess.get('channel') and not sess['channel'].closed:
        try:
            sess['channel'].resize_pty(width=data.get('cols', 120), height=data.get('rows', 40))
        except Exception:
            pass

@socketio.on('disconnect', namespace='/ssh')
def ssh_disconnect():
    _finalize_session(request.sid)

############################################## ERROR HANDLER #####################################################################
##################################################################################################################################

@app.errorhandler(403)
def forbidden(e):
    return render_template('base.html', error='Access denied'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', error='Page not found'), 404

############################################## APP START #########################################################################
##################################################################################################################################

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
