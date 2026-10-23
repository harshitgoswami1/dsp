"""Lab 9: hashing and reversible obfuscation demonstrations."""
import base64
import codecs
import hashlib
from hmac import compare_digest
from pathlib import Path
from urllib.parse import quote, unquote

ALGORITHMS = ('md5', 'sha1', 'sha256', 'sha512')


def hash_bytes(data):
    return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


def hash_text(text):
    return hash_bytes(text.encode('utf-8'))


def hash_file(path):
    hashes = {name: hashlib.new(name) for name in ALGORITHMS}
    with Path(path).open('rb') as file:
        for chunk in iter(lambda: file.read(65536), b''):
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def verify_hash(data, expected, algorithm='sha256'):
    if algorithm not in ALGORITHMS:
        raise ValueError('Unsupported algorithm')
    return compare_digest(hashlib.new(algorithm, data).hexdigest(), expected.lower())


def obfuscate(text, method, key=None):
    raw = text.encode('utf-8')
    if method == 'base64':
        return base64.b64encode(raw).decode('ascii')
    if method == 'hex':
        return raw.hex()
    if method == 'rot13':
        return codecs.encode(text, 'rot_13')
    if method == 'url':
        return quote(text, safe='')
    if method == 'xor':
        if not isinstance(key, int) or not 0 <= key <= 255:
            raise ValueError('XOR key must be an integer from 0 to 255')
        return bytes(byte ^ key for byte in raw).hex()
    raise ValueError('Unsupported method')


def deobfuscate(text, method, key=None):
    if method == 'base64':
        return base64.b64decode(text, validate=True).decode('utf-8')
    if method == 'hex':
        return bytes.fromhex(text).decode('utf-8')
    if method == 'rot13':
        return codecs.decode(text, 'rot_13')
    if method == 'url':
        return unquote(text)
    if method == 'xor':
        if not isinstance(key, int) or not 0 <= key <= 255:
            raise ValueError('XOR key must be an integer from 0 to 255')
        return bytes(byte ^ key for byte in bytes.fromhex(text)).decode('utf-8')
    raise ValueError('Unsupported method')
