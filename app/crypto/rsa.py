"""RSA encryption and decryption module."""

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_keys(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a pair of RSA keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key: RSAPrivateKey, public_key: RSAPublicKey) -> None:
    """Save the RSA keys to PEM files."""
    with Path("private_key.pem").open("wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with Path("public_key.pem").open("wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def load_private_key(path: str):
    with Path(path).open("rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def load_public_key(path: str):
    with Path(path).open("rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
        )

def encrypt(public_key, plaintext: str) -> bytes:
    """Encrypt data using the RSA public key."""
    return public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def decrypt(private_key, ciphertext: bytes) -> str:
    """Decrypt data using the RSA private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")
