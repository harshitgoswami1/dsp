"""Lab 10a: RSA-PSS signatures using SHA-256."""
import base64
import binascii
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def generate_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('ascii')
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('ascii')
    return {'private_key': private_pem, 'public_key': public_pem}


def sign(message, private_pem):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    signature = key.sign(message.encode('utf-8'), PADDING, hashes.SHA256())
    return base64.b64encode(signature).decode('ascii')


def verify(message, signature, public_pem):
    key = serialization.load_pem_public_key(public_pem.encode())
    try:
        key.verify(base64.b64decode(signature, validate=True), message.encode('utf-8'), PADDING, hashes.SHA256())
        return True
    except (InvalidSignature, binascii.Error):
        return False
