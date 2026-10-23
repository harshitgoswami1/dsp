"""Lab 3: confidentiality, integrity, and availability demonstrations."""
import hashlib
from cryptography.fernet import Fernet


def demonstrate(message, changed_message):
    if not isinstance(message, str) or not isinstance(changed_message, str):
        raise ValueError('message and changed_message must be strings')
    cipher = Fernet(Fernet.generate_key())
    encrypted = cipher.encrypt(message.encode('utf-8'))
    original_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    changed_hash = hashlib.sha256(changed_message.encode('utf-8')).hexdigest()
    return {
        'confidentiality': {'ciphertext': encrypted.decode('ascii'),
                            'decrypted': cipher.decrypt(encrypted).decode('utf-8')},
        'integrity': {'original_sha256': original_hash, 'changed_sha256': changed_hash,
                      'unchanged': original_hash == changed_hash},
        'availability': ['Service available', 'Simulated overload: service temporarily unavailable',
                         'Service restored'],
    }
