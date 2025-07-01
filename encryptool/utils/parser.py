"""Parser for command line arguments and configuration files."""
import argparse
import logging

logger = logging.getLogger("encryptool")


class Parser:
    """Parser for command line arguments and configuration."""

    def __init__(self) -> None:
        """Initialize the argument parser."""
        logger.debug("Initializing argument parser")
        self.parser = argparse.ArgumentParser(
            description="Encryption/Decryption Python tool",
        )
        self.subparsers = self.parser.add_subparsers(
            dest="command",
            help="Available commands",
        )
        self._setup_common_args()
        self._setup_encrypt_parser()
        self._setup_decrypt_parser()
        self._setup_signing_parser()
        self._setup_verifying_parser()
        logger.debug("Argument parser initialized with subparsers")

    def _setup_common_args(self) -> None:
        logger.debug("Setting up common arguments")
        self.parser.add_argument(
            "-m", "--mode",
            type=int,
            choices=[0, 1],
            default=1,
            help="Mode de chiffrement : 0=ADN, 1=RSA (par défaut)",
        )
        logger.debug("Common arguments set up")

    def _setup_encrypt_parser(self) -> None:
        logger.debug("Setting up encrypt parser")
        encrypt_parser = self.subparsers.add_parser("e", help="Encrypt")
        encrypt_parser.add_argument(
            "plaintext_path",
            nargs="?",
            type=str,
            help="File containing the message to encrypt",
        )
        encrypt_parser.add_argument(
            "--pubkey",
            type=str,
            help="Path to the public key file (RSA mode, defaults to public.pem)",
        )
        encrypt_parser.add_argument(
            "--privkey",
            type=str,
            help="Path to the private key file (RSA mode, defaults to private.pem)",
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
        encrypt_parser.add_argument(
            "--secret",
            type=str,
            help="Path to secret key file for DNA encryption",
        )
        encrypt_parser.add_argument(
            "-s",
            "--sign",
            action="store_true",
            help="Sign message after encryption",
            )
        logger.debug("Encrypt parser set up")

    def _setup_decrypt_parser(self) -> None:
        logger.debug("Setting up decrypt parser")
        decrypt_parser = self.subparsers.add_parser("d", help="Decrypt")
        decrypt_parser.add_argument(
            "ciphertext_path",
            nargs="?",
            type=str,
            help="File containing the ciphertext to decrypt",
        )
        decrypt_parser.add_argument(
            "--pubkey",
            type=str,
            help="Path to the public key file (RSA mode, defaults to public.pem)",
        )
        decrypt_parser.add_argument(
            "--privkey",
            type=str,
            help="Path to the private key file (RSA mode, defaults to private.pem)",
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
        decrypt_parser.add_argument(
            "--secret",
            type=str,
            help="Path to secret key file for DNA decryption",
        )
        decrypt_parser.add_argument(
            "-v",
            "--verify",
            action="store_true",
            help="Verify signature before decryption",
            )
        decrypt_parser.add_argument(
            "--signature-path",
            help="Path to the signature file for verification",
            )
        logger.debug("Decrypt parser set up")

    def _setup_signing_parser(self) -> None:
        logger.debug("Setting up signing parser")
        signing_parser = self.subparsers.add_parser("s", help="Sign a message")
        signing_parser.add_argument(
            "file_path",
            nargs="?",
            type=str,
            help="File containing the message to sign",
        )
        signing_parser.add_argument(
            "--privkey",
            type=str,
            help="Path to the private key file (RSA mode)",
        )
        signing_parser.add_argument(
            "--output-path", "-o",
            type=str,
            help="Path to save the signature (default: output/signature.txt)",
        )
        logger.debug("Signing parser set up")

    def _setup_verifying_parser(self) -> None:
        logger.debug("Setting up verifying parser")
        verifying_parser = self.subparsers.add_parser("v", help="Verify a signature")
        verifying_parser.add_argument(
            "file_path",
            nargs="?",
            type=str,
            help="File containing the signed message",
        )
        verifying_parser.add_argument(
            "--signature",
            type=str,
            help="Path to the signature file",
        )
        verifying_parser.add_argument(
            "--pubkey",
            type=str,
            help="Path to the public key file (RSA mode)",
        )
        logger.debug("Verifying parser set up")

    def parse_args(self) -> argparse.Namespace:
        """Parse and return the command line arguments."""
        logger.info("Parsing command line arguments")
        args = self.parser.parse_args()
        logger.debug("Arguments parsed: %s", args)
        if not args.command:
            logger.warning("No command provided")
        return args

    def print_help(self) -> None:
        """Print the help message."""
        logger.info("Printing help message")
        self.parser.print_help()
