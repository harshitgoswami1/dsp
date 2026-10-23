"""Lab 2: system, web-input, and encoding demonstrations."""
import platform
import re

SQL_MARKERS = re.compile(r'\b(?:select|drop|delete|insert|update|union)\b|--|/\*', re.I)


def system_info():
    return {'operating_system': platform.system(), 'version': platform.version(), 'machine': platform.machine()}


def inspect_input(text):
    if not isinstance(text, str):
        raise ValueError('text must be a string')
    return {'alphanumeric': text.isalnum(), 'sql_pattern_found': bool(SQL_MARKERS.search(text)),
            'note': 'These are pattern checks, not a complete security scan.'}


def hex_text(text, decode=False):
    if not isinstance(text, str):
        raise ValueError('text must be a string')
    return {'result': bytes.fromhex(text).decode('utf-8') if decode else text.encode('utf-8').hex()}