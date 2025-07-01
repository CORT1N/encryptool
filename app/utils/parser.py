"""Parser for command line arguments and configuration files."""
import argparse

parser = argparse.ArgumentParser(description="Encryption/Decryption Python tool")
subparsers = parser.add_subparsers(dest="command", help="Available commands")
parser.add_argument(
        "-m", "--mode",
        type=int,
        choices=[0, 1],
        default=1,
        help="Mode de chiffrement : 0=ADN, 1=RSA (par défaut)",
    )

encrypt_parser = subparsers.add_parser("e", help="Encrypt")
encrypt_parser.add_argument(
    "plaintext_path",
    nargs="?",
    type=str,
    help="File containing the message to encrypt",
)
encrypt_parser.add_argument(
    "--pubkey",
    type=str,
    help="Path to the public key file (RSA mode)",
)
encrypt_parser.add_argument(
    "--stdin",
    type=str,
    help="Read the text from stdin instead of a file",
)
encrypt_parser.add_argument(
    "--stdout",
    action="store_true",
    help="Print the ciphertext to stdout instead of saving to a file",
)
encrypt_parser.add_argument(
    "--output-path", "-o",
    type=str,
    help="Path to save the ciphertext (default: output/ciphertext.txt)",
)


decrypt_parser = subparsers.add_parser("d", help="Decrypt")
decrypt_parser.add_argument(
    "ciphertext_path",
    nargs="?",
    type=str,
    help="File containing the ciphertext to decrypt",
)
decrypt_parser.add_argument(
    "--privkey",
    type=str,
    help="Path to the private key file (RSA mode)",
)
decrypt_parser.add_argument(
    "--stdin",
    type=str,
    help="Read the ciphertext from stdin instead of a file",
)
decrypt_parser.add_argument(
    "--stdout",
    action="store_true",
    help="Print the plaintext to stdout instead of saving to a file",
)
decrypt_parser.add_argument(
    "--output-path", "-o",
    type=str,
    help="Path to save the plaintext (default: output/plaintext.txt)",
)
