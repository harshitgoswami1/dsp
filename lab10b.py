"""Lab 10b: in-memory users and role-based JWT authorization demo."""
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time

SECRET = os.environ.get('LAB_JWT_SECRET', secrets.token_hex(32)).encode()
USERS = {}


def _password_hash(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return salt.hex() + ':' + digest.hex()


def _check_password(password, stored):
    salt, _ = stored.split(':', 1)
    return hmac.compare_digest(_password_hash(password, bytes.fromhex(salt)), stored)


if os.environ.get('LAB_ADMIN_PASSWORD'):
    USERS[os.environ.get('LAB_ADMIN_USER', 'admin')] = {
        'password_hash': _password_hash(os.environ['LAB_ADMIN_PASSWORD']), 'role': 'admin'
    }


def register(username, password):
    if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or len(password) < 8:
        raise ValueError('Username is required and password must have at least 8 characters')
    if username in USERS:
        raise ValueError('User already exists')
    USERS[username] = {'password_hash': _password_hash(password), 'role': 'user'}


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64(data):
    return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))


def login(username, password):
    user = USERS.get(username)
    if not user or not isinstance(password, str) or not _check_password(password, user['password_hash']):
        raise ValueError('Invalid credentials')
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64(json.dumps({'sub': username, 'role': user['role'], 'exp': int(time.time()) + 3600}).encode())
    content = f'{header}.{payload}'
    signature = _b64(hmac.new(SECRET, content.encode(), hashlib.sha256).digest())
    return f'{content}.{signature}'


def authenticate(token, role=None):
    try:
        header, payload, signature = token.split('.')
        expected = _b64(hmac.new(SECRET, f'{header}.{payload}'.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        if json.loads(_unb64(header)) != {'alg': 'HS256', 'typ': 'JWT'}:
            raise ValueError()
        user = json.loads(_unb64(payload))
        if user['exp'] <= time.time() or user['sub'] not in USERS or USERS[user['sub']]['role'] != user['role']:
            raise ValueError()
    except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error):
        raise ValueError('Invalid or expired token') from None
    if role and user['role'] != role:
        raise PermissionError('Forbidden')
    return user
