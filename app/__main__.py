"""Entry point for the application."""
from __future__ import annotations

import argparse
from pathlib import Path

from app.crypto import dna, rsa
from app.utils.fs import load_private_key, load_public_key, save_keys
from app.utils.parser import parser

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def save_or_print(data: str, output_path: str | None, args: argparse.Namespace) -> None:
    """Save the data to a file or print it to stdout."""
    if output_path is None:
        print(data)
    else:
        if output_path == "":
            output_path = "ciphertext.txt" if args.mode == 1 else "plaintext.txt"
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / output_path
        output_file.write_text(data)
        print(f"Saved output to {output_file.resolve()}")

def encrypt_rsa(args: argparse.Namespace) -> None:
    """Encrypt a message using RSA."""
    if args.input:
        plaintext = Path(args.input).read_text()
    elif args.message:
        plaintext = args.message
    else:
        print(
            "Error: You must provide a message to encrypt"
            " either as positional argument or via --input/-i option.",
        )
        return

    pubkey_path = args.pubkey if args.pubkey else PUBLIC_KEY_PATH
    if not Path(pubkey_path).exists():
        print(f"Public key file not found: {pubkey_path}, generating new keys.")
        private_key, public_key = rsa.generate_keys()
        save_keys(private_key, public_key)
        print(f"Keys generated and saved to {PRIVATE_KEY_PATH} and {PUBLIC_KEY_PATH}.")

    public_key = load_public_key(pubkey_path)  # doit retourner un RSAPublicKey
    ciphertext_bytes = rsa.encrypt(public_key, plaintext)  # bytes
    save_or_print(ciphertext_bytes.hex(), args.output, args)


def decrypt_rsa(args: argparse.Namespace) -> None:
    """Decrypt a message using RSA."""
    privkey_path = args.privkey if args.privkey else PRIVATE_KEY_PATH
    if not Path(privkey_path).exists():
        print(f"Private key file not found: {privkey_path}.")
        return

    private_key = load_private_key(privkey_path)  # doit retourner un RSAPrivateKey

    try:
        if args.input:
            ciphertext_hex = Path(args.input).read_text().strip()
        elif args.ciphertext:
            ciphertext_hex = args.ciphertext.strip()
        else:
            print("Error: You must provide ciphertext either as a positional argument or via --input/-i option.")
            return
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = rsa.decrypt(private_key, ciphertext)  # retourne str
        save_or_print(plaintext, args.output, args)
    except Exception as e:
        print(f"Decryption failed: {e}")

def encrypt_dna(args: argparse.Namespace) -> None:
    """Encrypt a message using DNA encoding."""
    if args.input:
        plaintext = Path(args.input).read_text()
    elif args.message:
        plaintext = args.message
    else:
        print(
            "Error: You must provide a message to encrypt"
            " either as positional argument or via --input/-i option.",
        )
        return

    secret_key = "MaCleSecrete123"  # tu peux rendre ça paramétrable
    encrypted = dna.encrypt(plaintext, secret_key, timestamp=None)
    # encrypted est une string encodée (encrypted_dna:hash:timestamp)
    save_or_print(encrypted, args.output, args)

def decrypt_dna(args: argparse.Namespace) -> None:
    """Decrypt a message encoded in DNA."""
    if args.input:
        encoded = Path(args.input).read_text().strip()
    elif args.ciphertext:
        encoded = args.ciphertext.strip()
    else:
        print(
            "Error: You must provide ciphertext either as"
            " positional argument or via --input/-i option.",
        )
        return
    try:
        plaintext = dna.decrypt(encoded, secret_key="MaCleSecrete123", expected_hash=None, timestamp_tolerance=300)
        save_or_print(plaintext, args.output, args)
    except Exception as e:
        print(f"Decryption failed: {e}")

def main() -> None:
    """Launch the application."""
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
        parser.print_help()

if __name__ == "__main__":
    main()
