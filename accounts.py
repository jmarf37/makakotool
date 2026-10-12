"""Private accounts and encrypted credentials, backed by PostgreSQL."""
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import click
from cryptography.fernet import Fernet
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import select
from sqlalchemy.pool import NullPool
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()
csrf = CSRFProtect()
accounts = Blueprint('accounts', __name__)
SOURCES = {'VT_API': 'VirusTotal', 'ABUSE_API': 'AbuseIPDB', 'ALIEN_API': 'AlienVault OTX', 'IPQ_API': 'IPQualityScore'}
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


class User(db.Model):
    __tablename__ = 'makako_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    session_version = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_hex(32))
    encrypted_keys = db.Column(db.Text, nullable=False, default='')


class LoginWindow(db.Model):
    __tablename__ = 'makako_login_windows'
    key = db.Column(db.String(64), primary_key=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False)


def get_keys(user):
    if not user.encrypted_keys:
        return {}
    cipher = Fernet(current_app.config['API_KEYS_ENCRYPTION_KEY'])
    return json.loads(cipher.decrypt(user.encrypted_keys.encode()).decode())


def save_keys(user, keys):
    cipher = Fernet(current_app.config['API_KEYS_ENCRYPTION_KEY'])
    user.encrypted_keys = cipher.encrypt(json.dumps(keys).encode()).decode()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('accounts.login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def normalize_username(value):
    value = value.strip().lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,64}', value):
        raise ValueError('El usuario debe tener entre 3 y 64 caracteres: letras, números, punto, guion o guion bajo.')
    return value


def password_hash(value):
    if not 12 <= len(value) <= 128:
        raise ValueError('La contraseña debe tener entre 12 y 128 caracteres.')
    return generate_password_hash(value)


@accounts.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()[:64]
        password = request.form.get('password', '')
        # One shared PostgreSQL counter per account across all Vercel instances.
        key = hashlib.sha256(username.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        if db.engine.dialect.name == 'postgresql':
            from sqlalchemy.dialects.postgresql import insert
            db.session.execute(insert(LoginWindow).values(key=key, attempts=0, started_at=now).on_conflict_do_nothing(index_elements=['key']))
        elif not db.session.get(LoginWindow, key):  # SQLite is only used by tests.
            db.session.add(LoginWindow(key=key, attempts=0, started_at=now))
            db.session.flush()
        window = db.session.execute(select(LoginWindow).where(LoginWindow.key == key).with_for_update()).scalar_one()
        started = window.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        if now - started >= timedelta(minutes=15):
            window.started_at, window.attempts = now, 0
        if window.attempts >= 10:
            db.session.commit()
            return render_template('login.html', error='Demasiados intentos. Espera 15 minutos e inténtalo de nuevo.'), 429
        window.attempts += 1
        user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        valid = check_password_hash(user.password_hash if user else DUMMY_HASH, password[:128])
        if len(password) <= 128 and user and user.active and valid:
            window.attempts = 0
            db.session.commit()
            session.clear()
            session.permanent = True
            session['uid'] = user.id
            session['version'] = user.session_version
            return redirect(url_for('index'))
        db.session.commit()
        return render_template('login.html', error='Usuario o contraseña incorrectos.'), 401
    return render_template('login.html')


@accounts.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('accounts.login'))


@accounts.get('/admin')
@admin_required
def admin():
    users = db.session.execute(select(User).order_by(User.username)).scalars().all()
    # Only booleans are sent to the template; saved secrets never go to the browser.
    status = {u.id: {source: bool(get_keys(u).get(source)) for source in SOURCES} for u in users}
    return render_template('admin.html', users=users, sources=SOURCES, key_status=status)


@accounts.post('/admin/users')
@admin_required
def create_user():
    try:
        username = normalize_username(request.form.get('username', ''))
        hashed = password_hash(request.form.get('password', ''))
        if db.session.execute(select(User.id).where(User.username == username)).first():
            raise ValueError('Ese usuario ya existe.')
        db.session.add(User(username=username, password_hash=hashed, is_admin=False))
        db.session.commit()
        flash('Usuario creado. Ya puedes asignarle sus claves API.', 'success')
    except ValueError as e:
        flash(str(e), 'warning')
    return redirect(url_for('accounts.admin'))


@accounts.post('/admin/users/<int:user_id>')
@admin_required
def update_user(user_id):
    user = db.get_or_404(User, user_id)
    action = request.form.get('action')
    try:
        if action == 'toggle':
            if user.is_admin:
                raise ValueError('Las cuentas de administrador no se desactivan desde este panel.')
            user.active = not user.active
            user.session_version = secrets.token_hex(32)
            flash('Estado actualizado. Las sesiones anteriores quedan invalidadas.', 'success')
        elif action == 'password':
            user.password_hash = password_hash(request.form.get('password', ''))
            user.session_version = secrets.token_hex(32)
            flash('Contraseña actualizada. Las sesiones anteriores quedan invalidadas.', 'success')
        elif action == 'keys':
            keys = get_keys(user)
            for source in SOURCES:
                value = request.form.get(source, '').strip()
                if request.form.get('delete_' + source) == 'on':
                    keys.pop(source, None)
                elif value:
                    if len(value) > 512 or any(c.isspace() for c in value):
                        raise ValueError('Las claves no pueden contener espacios ni superar 512 caracteres.')
                    keys[source] = value
            save_keys(user, keys)
            flash('Claves guardadas para este usuario.', 'success')
        else:
            abort(400)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        flash(str(e), 'warning')
    return redirect(url_for('accounts.admin'))


def init_accounts(app):
    database_url = os.getenv('DATABASE_URL', '')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
    elif database_url.startswith('postgresql://'):
        database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY'),
        API_KEYS_ENCRYPTION_KEY=os.getenv('API_KEYS_ENCRYPTION_KEY'),
        SQLALCHEMY_DATABASE_URI=database_url or 'sqlite:///:memory:',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={'poolclass': NullPool, 'connect_args': {'connect_timeout': 10}} if database_url else {},
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    db.init_app(app)

    @app.before_request
    def load_account():
        g.user = None
        if request.endpoint in {'static', 'logo'}:
            return
        if not all(app.config.get(k) for k in ('SECRET_KEY', 'API_KEYS_ENCRYPTION_KEY')) or (not database_url and not app.testing):
            return render_template('service_error.html'), 503
        Fernet(app.config['API_KEYS_ENCRYPTION_KEY'])
        uid = session.get('uid')
        if uid is not None:
            user = db.session.get(User, uid)
            if user and user.active and secrets.compare_digest(user.session_version, session.get('version', '')):
                g.user = user
            else:
                session.clear()

    csrf.init_app(app)
    app.register_blueprint(accounts)

    @app.after_request
    def security_headers(response):
        if request.endpoint not in {'static', 'logo'}:
            response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        return response

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        return render_template('service_error.html'), 500

    @app.cli.command('init-db')
    def init_db():
        if not database_url:
            raise click.ClickException('Configura DATABASE_URL antes de inicializar.')
        db.create_all()
        click.echo('Tablas creadas.')

    @app.cli.command('create-admin')
    @click.option('--username', prompt='Usuario administrador')
    @click.option('--password', prompt='Contraseña', hide_input=True, confirmation_prompt=True)
    def create_admin(username, password):
        if not database_url:
            raise click.ClickException('Configura DATABASE_URL antes de crear el administrador.')
        try:
            username = normalize_username(username)
            hashed = password_hash(password)
        except ValueError as e:
            raise click.ClickException(str(e)) from None
        if db.session.execute(select(User.id).where(User.username == username)).first():
            raise click.ClickException('El usuario ya existe; no se sobrescribirá.')
        db.session.add(User(username=username, password_hash=hashed, is_admin=True))
        db.session.commit()
        click.echo('Administrador creado.')
