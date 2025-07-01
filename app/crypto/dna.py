"""Custom DNA encryption class using POO."""

from __future__ import annotations

import hashlib
import logging
import random
import time
from typing import TypedDict

logger = logging.getLogger("encryptool")


class EncryptedDNAData(TypedDict):
    """Data structure for encrypted DNA information."""

    encrypted_dna: str
    hash: str
    timestamp: int
    message_length: int


class DNAEngine:
    """Encryptor class for DNA-based encryption and decryption."""

    def __init__(self, secret_key: str, timestamp_tolerance: int = 300) -> None:
        """Initialize the DNAEngine."""
        self.secret_key = secret_key
        self.timestamp_tolerance = timestamp_tolerance
        logger.info(
            "DNAEngine initialized with timestamp tolerance %s", timestamp_tolerance,
            )

    @staticmethod
    def _byte_to_dna(byte: int) -> str:
        bin_str = f"{byte:08b}"
        mapping = {"00": "A", "01": "C", "10": "G", "11": "T"}
        result = "".join(mapping[bin_str[i:i+2]] for i in range(0, 8, 2))
        logger.debug("_byte_to_dna: %s -> %s", byte, result)
        return result

    @staticmethod
    def _dna_to_byte(dna: str) -> int:
        rev_map = {"A": "00", "C": "01", "G": "10", "T": "11"}
        bits = "".join(rev_map[b] for b in dna)
        result = int(bits, 2)
        logger.debug("_dna_to_byte: %s -> %s", dna, result)
        return result

    @classmethod
    def _message_to_dna(cls, message: str) -> str:
        result = "".join(cls._byte_to_dna(ord(c)) for c in message)
        logger.debug(
            "_message_to_dna: message length %s -> dna length %s",
            len(message),
            len(result),
            )
        return result

    @classmethod
    def _dna_to_message(cls, dna: str) -> str:
        chars = [
            chr(cls._dna_to_byte(dna[i:i+4]))
            for i in range(0, len(dna), 4)
        ]
        result = "".join(chars)
        logger.debug(
            "_dna_to_message: dna length %s -> message length %s",
            len(dna),
            len(result),
            )
        return result

    @staticmethod
    def _compute_hash(data_str: str) -> str:
        result = hashlib.sha256(data_str.encode()).hexdigest()
        logger.debug(
            "_compute_hash: computed hash %s for data of length %s",
            result,
            len(data_str),
            )
        return result

    @staticmethod
    def _get_timestamp() -> int:
        result = int(time.time())
        logger.debug(
            "_get_timestamp: %s",
            result,
            )
        return result

    def _get_permutation(self, n: int, seed_hex: str) -> list[int]:
        seed_int = int(seed_hex, 16)
        random.seed(seed_int)
        indices = list(range(n))
        random.shuffle(indices)
        logger.debug(
            "_get_permutation: generated permutation of length %s with seed %s",
            n,
            seed_hex,
            )
        return indices

    def _permute_block(self, block: str, seed_hex: str) -> tuple[str, list[int]]:
        indices = self._get_permutation(len(block), seed_hex)
        permuted = "".join(block[i] for i in indices)
        logger.debug(
            "_permute_block: block permuted from %s to %s",
            block,
            permuted,
            )
        return permuted, indices

    def _inverse_permute_block(self, block: str, indices: list[int]) -> str:
        original = [""] * len(block)
        for i, c in enumerate(block):
            original[indices[i]] = c
        result = "".join(original)
        logger.debug("_inverse_permute_block: block inverse permuted to %s", result)
        return result

    def encrypt(self, message: str, timestamp: int | None = None) -> str:
        """Encrypt a message into DNA format with a timestamp."""
        logger.info("Starting encryption")
        if timestamp is None:
            timestamp = self._get_timestamp()
            logger.debug("No timestamp provided, using current timestamp %s", timestamp)

        dna = self._message_to_dna(message)
        block_size = 8
        if len(dna) % block_size != 0:
            padding_len = block_size - (len(dna) % block_size)
            dna += "A" * padding_len
            logger.debug("Padded DNA with %s 'A's", padding_len)

        blocks = [dna[i:i+block_size] for i in range(0, len(dna), block_size)]
        encrypted_blocks = []

        for i, block in enumerate(blocks):
            seed_str = f"{self.secret_key}{timestamp}{i}"
            seed_hex = self._compute_hash(seed_str)
            permuted_block, _ = self._permute_block(block, seed_hex)
            encrypted_blocks.append(permuted_block)

        encrypted_dna = "".join(encrypted_blocks)
        hash_str = self._compute_hash(message + str(timestamp))
        message_length = len(message)

        logger.info("Encryption complete")
        return f"{encrypted_dna}:{hash_str}:{timestamp}:{message_length}"

    def decrypt(self, encoded: str, expected_hash: str | None = None) -> str:
        """Decrypt a DNA-encoded message."""
        logger.info("Starting decryption")
        parts = encoded.split(":")
        parts_length = 4
        if len(parts) != parts_length:
            e = "Invalid encoded DNA format"
            logger.error(e)
            raise ValueError(e)

        encrypted_dna, hash_str, timestamp_str, length_str = parts
        timestamp = int(timestamp_str)
        message_length = int(length_str)

        block_size = 8
        blocks = [
            encrypted_dna[i:i+block_size]
            for i in range(0, len(encrypted_dna), block_size)
        ]

        decrypted_blocks = []
        for i, block in enumerate(blocks):
            seed_str = f"{self.secret_key}{timestamp}{i}"
            seed_hex = self._compute_hash(seed_str)
            indices = self._get_permutation(len(block), seed_hex)
            decrypted_blocks.append(self._inverse_permute_block(block, indices))

        decrypted_dna = "".join(decrypted_blocks)
        decrypted_dna = decrypted_dna[:message_length * 4]
        message = self._dna_to_message(decrypted_dna)

        recomputed_hash = self._compute_hash(message + str(timestamp))
        if expected_hash and expected_hash != recomputed_hash:
            e = "Provided hash does not match recomputed hash"
            logger.error(e)
            raise ValueError(e)
        if hash_str != recomputed_hash:
            e = "Hash in encrypted data does not match recomputed hash"
            logger.error(e)
            raise ValueError(e)

        now = self._get_timestamp()
        if abs(now - timestamp) > self.timestamp_tolerance:
            e = f"Timestamp tolerance exceeded: {now} - {timestamp}"
            logger.error(e)
            raise ValueError(e)

        logger.info("Decryption successful")
        return message
