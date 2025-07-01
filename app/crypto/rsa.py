"""RSA encryption and decryption module."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.utils.logger import logger

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
        logger.info(
            f"RSAEngine initialized with privkey_path={self._privkey_path},"
            f" pubkey_path={self._pubkey_path}",
            )

    def generate_keys(self, key_size: int = 2048) -> None:
        """Generate a new RSA key pair and save them to disk."""
        logger.info(f"Generating RSA keys with key size {key_size}")
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self._public_key = self._private_key.public_key()
        self._save_keys()
        logger.info("RSA keys generated and saved")

    def _save_keys(self) -> None:
        """Save private and public keys to PEM files."""
        if not self._private_key or not self._public_key:
            e = "Keys must be generated or loaded before saving."
            logger.error(e)
            raise ValueError(e)

        with self._privkey_path.open("wb") as f:
            f.write(
                self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
            logger.debug(f"Private key saved to {self._privkey_path}")

        with self._pubkey_path.open("wb") as f:
            f.write(
                self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            logger.debug(f"Public key saved to {self._pubkey_path}")

    def _load_private_key(self) -> RSAPrivateKey:
        """Load private key from file or generate if missing."""
        if not self._privkey_path.exists():
            logger.warning(
                f"Private key not found at {self._privkey_path}, generating new keys.",
                )
            self.generate_keys()
        with self._privkey_path.open("rb") as f:
            self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.debug(f"Private key loaded from {self._privkey_path}")
        return self._private_key

    def _load_public_key(self) -> RSAPublicKey:
        """Load public key from file or generate if missing."""
        if not self._pubkey_path.exists():
            logger.warning(
                f"Public key not found at {self._pubkey_path}, generating new keys.",
                )
            self.generate_keys()
        with self._pubkey_path.open("rb") as f:
            self._public_key = serialization.load_pem_public_key(f.read())
            logger.debug(f"Public key loaded from {self._pubkey_path}")
        return self._public_key

    def _ensure_keys_loaded(self) -> None:
        """Ensure both private and public keys are loaded."""
        if self._private_key is None:
            logger.debug("Private key not loaded, loading now")
            self._load_private_key()
        if self._public_key is None:
            logger.debug("Public key not loaded, loading now")
            self._load_public_key()

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt plaintext using the public key."""
        logger.info("Starting encryption")
        self._load_public_key()
        ciphertext = self._public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        logger.info("Encryption complete")
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt ciphertext using the private key."""
        logger.info("Starting decryption")
        self._load_private_key()
        plaintext = self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        result = plaintext.decode("utf-8")
        logger.info("Decryption complete")
        return result

    def sign(self, message: str) -> bytes:
        """Sign message using the private key."""
        logger.info("Signing message")
        self._load_private_key()
        signature = self._private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logger.info("Message signed")
        return signature

    def verify(self, message: str, signature: bytes) -> bool:
        """Verify signature using the public key."""
        logger.info("Verifying signature")
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
            logger.warning("Signature verification failed")
            return False
        else:
            logger.info("Signature verified successfully")
            return True
