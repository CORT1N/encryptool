"""RSA encryption and decryption module."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )


class RSAEngine:
    """RSA Engine for encrypting, decrypting, signing, and verifying messages."""

    PRIVATE_KEY_PATH = "private_key.pem"
    PUBLIC_KEY_PATH = "public_key.pem"

    def __init__(
        self,
        privkey_path: str | None = None,
        pubkey_path: str | None = None,
        ) -> None:
        """Initialize the RSA engine."""
        self.privkey_path = privkey_path or self.PRIVATE_KEY_PATH
        self.pubkey_path = pubkey_path or self.PUBLIC_KEY_PATH
        self.private_key: RSAPrivateKey
        self.public_key: RSAPublicKey

    def generate_keys(self, key_size: int = 2048) -> None:
        """Generate a new pair of RSA keys."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            )
        self.public_key = self.private_key.public_key()
        self.save_keys()

    def save_keys(self) -> None:
        """Save RSA keys to PEM files."""
        if not self.private_key:
            e = "Private key is not available. Generate or load keys first."
            raise ValueError(e)
        with Path("private_key.pem").open("wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        if not self.public_key:
                e = "Public key is not available. Generate or load keys first."
                raise ValueError(e)
        with Path("public_key.pem").open("wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def load_private_key(self) -> RSAPrivateKey:
        """Load the RSA private key from a PEM file."""
        try:
            with Path(self.privkey_path).open("rb") as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
        except FileNotFoundError:
            print(f"Private key file not found: {self.privkey_path}, generating new keys.")
            self.generate_keys()
            return self.load_private_key()

    def load_public_key(self) -> RSAPublicKey:
        """Load the RSA public key from a PEM file."""
        if not Path(self.pubkey_path).exists():
            print(f"Public key file not found: {self.pubkey_path}, generating new keys.")
            self.generate_keys()
        with Path(self.pubkey_path).open("rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())
        return self.public_key

    def load_keys(self) -> None:
        """Load both private and public keys."""
        self.private_key = self.load_private_key()
        self.public_key = self.load_public_key()

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt data using the RSA public key."""
        self.public_key = self.load_public_key()
        return self.public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt data using the RSA private key."""
        self.private_key = self.load_private_key()
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")

    def sign(self, message: str) -> bytes:
        """Sign a message using the RSA private key."""
        return self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, message: str, signature: bytes) -> bool:
        """Verify a signature using the RSA public key."""
        try:
            self.public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        else:
            return True
