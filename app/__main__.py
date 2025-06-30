"""Entry point for the application."""
from __future__ import annotations

import argparse
from pathlib import Path

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def main():
    parser = argparse.ArgumentParser(description="Encryption/Decryption Python tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    encrypt_parser = subparsers.add_parser("e", help="Encrypt")
    encrypt_parser.add_argument("message", nargs="?", type=str, help="Message to encrypt")
    encrypt_parser.add_argument(
        "--pubkey",
        type=str,
        help="Path to the public key file",
    )
    encrypt_parser.add_argument(
        "--input", "-i",
        type=str,
        help="Path to input file containing plaintext",
    )
    encrypt_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file to save the ciphertext",
        nargs="?",
        const="ciphertext.txt",
    )

    decrypt_parser = subparsers.add_parser("d", help="Decrypt")
    decrypt_parser.add_argument("ciphertext", nargs="?", type=str, help="Ciphertext to decrypt")
    decrypt_parser.add_argument(
        "--privkey",
        type=str,
        help="Path to the private key file",
    )
    decrypt_parser.add_argument(
        "--input", "-i",
        type=str,
        help="Path to input file containing ciphertext in hex",
    )
    decrypt_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file to save the plaintext",
        nargs="?",
        const="plaintext.txt",
    )

    args = parser.parse_args()

    def save_or_print(data: str, output_path: str | None):
        if output_path is None:
            print(data)
        else:
            if output_path == "":
                if args.command == "e":
                    output_path = "ciphertext"
                else:
                    output_path = "plaintext"
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            output_file = output_dir / output_path
            output_file.write_text(data)
            print(f"Saved output to {output_file.resolve()}")

    if args.command == "e":
        if args.input:
            plaintext = Path(args.input).read_text()
        elif args.message:
            plaintext = args.message
        else:
            print("Error: You must provide a message to encrypt either as positional argument or via --input/-i option.")
            return

        pubkey_path = args.pubkey if args.pubkey else PUBLIC_KEY_PATH
        from app.crypto.rsa import encrypt, load_public_key
        if not Path(pubkey_path).exists():
            print(f"Public key file not found: {pubkey_path}, generating new keys.")
            from app.crypto.rsa import generate_keys, save_keys
            private_key, public_key = generate_keys()
            save_keys(private_key, public_key)
            print(f"Keys generated and saved to {PRIVATE_KEY_PATH} and {PUBLIC_KEY_PATH}.")
        public_key = load_public_key(pubkey_path)
        ciphertext = encrypt(public_key, plaintext)
        save_or_print(ciphertext.hex(), args.output)

    elif args.command == "d":
        privkey_path = args.privkey if args.privkey else PRIVATE_KEY_PATH
        from app.crypto.rsa import decrypt, load_private_key
        if not Path(privkey_path).exists():
            print(f"Private key file not found: {privkey_path}.")
            return
        private_key = load_private_key(privkey_path)
        try:
            if args.input:
                ciphertext_hex = Path(args.input).read_text().strip()
            elif args.ciphertext:
                ciphertext_hex = args.ciphertext
            else:
                print("Error: You must provide ciphertext either as a positional argument or via --input/-i option.")
                return
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = decrypt(private_key, ciphertext)
            save_or_print(plaintext, args.output)
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
