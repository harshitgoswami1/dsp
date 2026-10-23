"""Lab 1: small introductory security exercises."""
import socket


def password_strength(password):
    if not isinstance(password, str):
        raise ValueError('password must be text')
    return {'length': len(password), 'good_length': len(password) >= 8,
            'message': 'Password length is good' if len(password) >= 8 else 'Use at least 8 characters'}


def demo_login(username, password):
    return {'success': username == 'student' and password == '1234'}


def network_info():
    hostname = socket.gethostname()
    try:
        address = socket.gethostbyname(hostname)
    except OSError:
        address = 'Unavailable'
    return {'server_hostname': hostname, 'server_local_ip': address}


def caesar(text, shift=3):
    if not isinstance(text, str) or not isinstance(shift, int) or isinstance(shift, bool):
        raise ValueError('text and integer shift are required')
    shift %= 26
    result = []
    for char in text:
        if 'A' <= char <= 'Z':
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif 'a' <= char <= 'z':
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return {'result': ''.join(result)}


def hex_text(text, decode=False):
    if not isinstance(text, str):
        raise ValueError('text must be a string')
    return {'result': bytes.fromhex(text).decode('utf-8') if decode else text.encode('utf-8').hex()}
