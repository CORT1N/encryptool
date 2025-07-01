"""Entry point for the CLI application."""
from __future__ import annotations

import logging
from getpass import getpass
from pathlib import Path
from typing import TYPE_CHECKING

from encryptool.crypto.dna import DNAEngine
from encryptool.crypto.rsa import RSAEngine
from encryptool.utils.parser import Parser

logger = logging.getLogger("encryptool")

if TYPE_CHECKING:
    import argparse

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def setup_logging() -> None:
    """Configure the logging settings."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

def save_or_print(data: str, args: argparse.Namespace, default_name: str) -> None:
    """Save the data to a file or print it to stdout depending on args.stdout."""
    if args.stdout:
        logger.info("Outputting data to stdout")
        print(data) #noqa: T201
    else:
        if args.output_path:
            output_path = Path(args.output_path)
        else:
            output_path = Path("output") / default_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(data)
        logger.info("Saved output to %s", output_path.resolve())

def get_secret_key(args: argparse.Namespace) -> str:
    """Get secret key for DNA encryption/decryption.

    - If --secret is given, read secret from that file
    - Else if --privkey is given, derive secret from private key file contents
    - Else prompt the user for the secret interactively
    """
    if hasattr(args, "secret") and args.secret:
        secret_path = Path(args.secret)
        if secret_path.exists():
            return secret_path.read_text().strip()
        e = f"Secret file not found: {secret_path}"
        raise FileNotFoundError(e)

    secret = getpass("Enter secret key for DNA encryption/decryption: ")
    return secret.strip()

def read_input(args: argparse.Namespace, file_attr: str) -> str | None:
    """Read plaintext or ciphertext from file or stdin."""
    if args.stdin:
        logger.info("Reading input from stdin")
        return args.stdin
    file_path = getattr(args, file_attr)
    if file_path:
        logger.info("Reading input from file %s", file_path)
        return Path(file_path).read_text()
    logger.error("No input provided (use a file or --stdin)")
    return None


def encrypt_rsa(args: argparse.Namespace) -> None:
    """Encrypt plaintext using RSA."""
    logger.info("Starting RSA encryption")
    plaintext = read_input(args, "plaintext_path")
    if plaintext is None:
        logger.error("No plaintext to encrypt")
        return

    pubkey_path = args.pubkey if args.pubkey else PUBLIC_KEY_PATH
    engine = RSAEngine(pubkey_path=pubkey_path)
    ciphertext_bytes = engine.encrypt(plaintext)
    save_or_print(ciphertext_bytes.hex(), args, "ciphertext.txt")
    if getattr(args, "sign", False):
        privkey_path = args.privkey if args.privkey else PRIVATE_KEY_PATH
        engine = RSAEngine(privkey_path=privkey_path)
        signature = engine.sign(plaintext)
        save_or_print(signature.hex(), args, "signature.txt")
        logger.info("Message signed after encryption")
    logger.info("RSA encryption completed")


def decrypt_rsa(args: argparse.Namespace) -> None:
    """Decrypt ciphertext using RSA."""
    logger.info("Starting RSA decryption")
    ciphertext_hex = read_input(args, "ciphertext_path")
    if ciphertext_hex is None:
        logger.error("No ciphertext to decrypt")
        return

    privkey_path = args.privkey if args.privkey else PRIVATE_KEY_PATH
    engine = RSAEngine(privkey_path=privkey_path)
    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
        if getattr(args, "verify", False):
            signature_hex = read_input(args, "signature_path")
            if signature_hex is None:
                logger.error("No signature provided for verification")
                return

            pubkey_path = args.pubkey if args.pubkey else PUBLIC_KEY_PATH
            verify_engine = RSAEngine(pubkey_path=pubkey_path)
            signature = bytes.fromhex(signature_hex.strip())
            plaintext = engine.decrypt(ciphertext)

            if not verify_engine.verify(plaintext, signature):
                return
        else:
            plaintext = engine.decrypt(ciphertext)
        save_or_print(plaintext, args, "plaintext.txt")
        logger.info("RSA decryption completed")
    except Exception:
        logger.exception("Decryption failed.")

def sign_rsa(args: argparse.Namespace) -> None:
    """Sign a message using RSA."""
    logger.info("Starting RSA signing")
    message = read_input(args, "message_path")
    if message is None:
        logger.error("No message to sign")
        return

    privkey_path = args.privkey if args.privkey else PRIVATE_KEY_PATH
    engine = RSAEngine(privkey_path=privkey_path)
    signature = engine.sign(message)
    save_or_print(signature.hex(), args, "signature.txt")
    logger.info("RSA signing completed")


def verify_rsa(args: argparse.Namespace) -> None:
    """Verify a signature using RSA."""
    logger.info("Starting RSA signature verification")

    message = read_input(args, "file_path")
    if message is None:
        logger.error("No message provided for verification")
        return

    signature_hex = read_input(args, "signature_path")
    if signature_hex is None:
        logger.error("No signature provided for verification")
        return

    pubkey_path = args.pubkey if args.pubkey else PUBLIC_KEY_PATH
    engine = RSAEngine(pubkey_path=pubkey_path)
    signature = bytes.fromhex(signature_hex.strip())

    if engine.verify(message, signature):
        logger.info("Signature verification successful")
    else:
        logger.warning("Signature verification failed")

def encrypt_dna(args: argparse.Namespace) -> None:
    """Encrypt plaintext using DNA encryption."""
    logger.info("Starting DNA encryption")
    plaintext = read_input(args, "plaintext_path")
    if plaintext is None:
        logger.error("No plaintext to encrypt")
        return
    try:
        secret_key = get_secret_key(args)
    except Exception:
        logger.exception("Failed to get secret key.")
        return

    engine = DNAEngine(secret_key=secret_key)
    encrypted = engine.encrypt(plaintext)
    save_or_print(encrypted, args, "ciphertext.txt")
    logger.info("DNA encryption completed")


def decrypt_dna(args: argparse.Namespace) -> None:
    """Decrypt ciphertext using DNA encryption."""
    logger.info("Starting DNA decryption")
    encoded = read_input(args, "ciphertext_path")
    if encoded is None:
        logger.error("No ciphertext to decrypt")
        return
    try:
        secret_key = get_secret_key(args)
    except Exception:
        logger.exception("Failed to get secret key.")
        return

    try:
        engine = DNAEngine(secret_key=secret_key)
        plaintext = engine.decrypt(encoded.strip())
        save_or_print(plaintext, args, "plaintext.txt")
        logger.info("DNA decryption completed")
    except Exception:
        logger.exception("Decryption failed.")


def main() -> None:
    """Launch the application."""
    setup_logging()
    logger.info("Application started")
    parser = Parser()
    args = parser.parse_args()

    if args.command == "e":
        if args.mode == 0:
            encrypt_dna(args)
        else:
            encrypt_rsa(args)
    elif args.command == "d":
        if args.mode == 0:
            decrypt_dna(args)
        else:
            decrypt_rsa(args)
    elif args.command == "s":
        sign_rsa(args)
    elif args.command == "v":
        verify_rsa(args)
    else:
        logger.warning("Unknown command: %s", args.command)
        parser.print_help()

    logger.info("Application finished")


if __name__ == "__main__":
    main()
