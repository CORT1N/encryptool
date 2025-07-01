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
    "message",
    nargs="?",
    type=str,
    help="Message to encrypt",
)
encrypt_parser.add_argument(
    "--pubkey",
    type=str,
    help="Path to the public key file (RSA mode)",
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
decrypt_parser.add_argument(
    "ciphertext",
    nargs="?",
    type=str,
    help="Ciphertext to decrypt",
)
decrypt_parser.add_argument(
    "--privkey",
    type=str,
    help="Path to the private key file (RSA mode)",
)
decrypt_parser.add_argument(
    "--input", "-i",
    type=str,
    help="Path to input file containing ciphertext",
)
decrypt_parser.add_argument(
    "-o", "--output",
    type=str,
    help="Output file to save the plaintext",
    nargs="?",
    const="plaintext.txt",
)
