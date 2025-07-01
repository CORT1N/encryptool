"""Filesystem utilities for handling file operations."""
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def save_keys(private_key: RSAPrivateKey, public_key: RSAPublicKey) -> None:
    """Save RSA keys to PEM files."""
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
