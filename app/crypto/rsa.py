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

    DEFAULT_PRIVATE_KEY_PATH = "private_key.pem"
    DEFAULT_PUBLIC_KEY_PATH = "public_key.pem"

    def __init__(
        self,
        privkey_path: str | None = None,
        pubkey_path: str | None = None,
    ) -> None:
        """Initialize the RSA engine."""
        self._privkey_path = Path(privkey_path or self.DEFAULT_PRIVATE_KEY_PATH)
        self._pubkey_path = Path(pubkey_path or self.DEFAULT_PUBLIC_KEY_PATH)
        self._private_key: RSAPrivateKey | None = None
        self._public_key: RSAPublicKey | None = None

    def generate_keys(self, key_size: int = 2048) -> None:
        """Generate a new RSA key pair and save them to disk."""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self._public_key = self._private_key.public_key()
        self._save_keys()

    def _save_keys(self) -> None:
        """Save private and public keys to PEM files."""
        if not self._private_key or not self._public_key:
            e = "Keys must be generated or loaded before saving."
            raise ValueError(e)

        with self._privkey_path.open("wb") as f:
            f.write(
                self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )

        with self._pubkey_path.open("wb") as f:
            f.write(
                self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )

    def _load_private_key(self) -> RSAPrivateKey:
        """Load private key from file or generate if missing."""
        if not self._privkey_path.exists():
            print(f"Private key not found at {self._privkey_path}, generating new keys.")
            self.generate_keys()
        with self._privkey_path.open("rb") as f:
            self._private_key = serialization.load_pem_private_key(f.read(), password=None)
        return self._private_key

    def _load_public_key(self) -> RSAPublicKey:
        """Load public key from file or generate if missing."""
        if not self._pubkey_path.exists():
            print(f"Public key not found at {self._pubkey_path}, generating new keys.")
            self.generate_keys()
        with self._pubkey_path.open("rb") as f:
            self._public_key = serialization.load_pem_public_key(f.read())
        return self._public_key

    def _ensure_keys_loaded(self) -> None:
        """Ensure both private and public keys are loaded."""
        if self._private_key is None:
            self._load_private_key()
        if self._public_key is None:
            self._load_public_key()

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt plaintext using the public key."""
        self._load_public_key()
        return self._public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt ciphertext using the private key."""
        self._load_private_key()
        plaintext = self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")

    def sign(self, message: str) -> bytes:
        """Sign message using the private key."""
        self._load_private_key()
        return self._private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, message: str, signature: bytes) -> bool:
        """Verify signature using the public key."""
        self._load_public_key()
        try:
            self._public_key.verify(
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
