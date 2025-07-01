"""Entry point for the application."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from app.crypto.dna import DNAEngine  # <- Le nom du module POO refacto
from app.crypto.rsa import RSAEngine
from app.utils.logger import logger  # import du logger
from app.utils.parser import Parser

if TYPE_CHECKING:
    import argparse

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"
DEFAULT_SECRET = "MaCleSecrete123"


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
        logger.info(f"Saved output to {output_path.resolve()}")


def read_input(args: argparse.Namespace, file_attr: str) -> str | None:
    """Read plaintext or ciphertext from file or stdin."""
    if args.stdin:
        logger.info("Reading input from stdin")
        return args.stdin
    file_path = getattr(args, file_attr)
    if file_path:
        logger.info(f"Reading input from file {file_path}")
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
        plaintext = engine.decrypt(ciphertext)
        save_or_print(plaintext, args, "plaintext.txt")
        logger.info("RSA decryption completed")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")


def encrypt_dna(args: argparse.Namespace) -> None:
    """Encrypt plaintext using DNA encryption."""
    logger.info("Starting DNA encryption")
    plaintext = read_input(args, "plaintext_path")
    if plaintext is None:
        logger.error("No plaintext to encrypt")
        return

    engine = DNAEngine(secret_key=DEFAULT_SECRET)
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
        engine = DNAEngine(secret_key=DEFAULT_SECRET)
        plaintext = engine.decrypt(encoded.strip())
        save_or_print(plaintext, args, "plaintext.txt")
        logger.info("DNA decryption completed")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")


def main() -> None:
    """Launch main function."""
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
    else:
        logger.warning(f"Unknown command: {args.command}")
        parser.print_help()

    logger.info("Application finished")


if __name__ == "__main__":
    main()
