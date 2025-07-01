"""Custom encryption module guaranteeing the 4 cryptography basics."""
from __future__ import annotations

import hashlib
import random
import time
from typing import TypedDict


def byte_to_dna(byte: int) -> str:
    """Convert 1 byte to dna string (8 bits → 4 DNA bases)."""
    bin_str = f"{byte:08b}"
    mapping = {"00":"A", "01":"C", "10":"G", "11":"T"}
    dna = ""
    for i in range(0, 8, 2):
        bits = bin_str[i:i+2]
        dna += mapping[bits]
    return dna

def dna_to_byte(dna: str) -> int:
    """Convert 4 DNA bases to 1 byte (8 bits)."""
    rev_map = {"A":"00", "C":"01", "G":"10", "T":"11"}
    bits = "".join(rev_map[b] for b in dna)
    return int(bits, 2)

def message_to_dna(message: str) -> str:
    """Convert message string to DNA string."""
    return "".join(byte_to_dna(ord(c)) for c in message)

def dna_to_message(dna: str) -> str:
    """Convert dna string back to message string."""
    chars = []
    for i in range(0, len(dna), 4):
        byte = dna_to_byte(dna[i:i+4])
        chars.append(chr(byte))
    return "".join(chars)

def permute_block(block: str, key_seed: str) -> str:
    """Swap a block of DNA bases using a key seed."""
    random.seed(key_seed)
    block_list = list(block)
    random.shuffle(block_list)
    return "".join(block_list)

def inverse_permute_block(permuted_block: str, key_seed: str) -> str:
    """Reverse the permutation of a DNA block using the same key seed."""
    random.seed(key_seed)
    block_list = list(permuted_block)
    original_indices = list(range(len(block_list)))
    shuffled_indices = original_indices[:]
    random.shuffle(shuffled_indices)
    inverse_indices = [0] * len(block_list)
    for i, shuffled_idx in enumerate(shuffled_indices):
        inverse_indices[shuffled_idx] = i
    original_block = [""] * len(block_list)
    for i, c in enumerate(block_list):
        original_block[inverse_indices[i]] = c
    return "".join(original_block)

def compute_hash(data_str: str) -> str:
    """Compute SHA256 hash of a string."""
    return hashlib.sha256(data_str.encode()).hexdigest()

def hash_to_int(hash_hex: str) -> int:
    """Convert a hexadecimal hash string to an integer."""
    return int(hash_hex, 16)

def get_timestamp() -> int:
    """Return current timestamp in seconds."""
    return int(time.time())

class EncryptedDNAData(TypedDict):
    """Class for encrypted DNA data structure."""

    encrypted_dna: str
    hash: str
    timestamp: int

def encode_encrypted_dna(encrypted_dna: str, hash_str: str, timestamp: int) -> str:
    """Encode the encrypted dna, hash, and timestamp into a single string."""
    return f"{encrypted_dna}:{hash_str}:{timestamp}"

def decode_encrypted_dna(encoded_str: str) -> EncryptedDNAData:
    """Decode the encoded dna string into its components."""
    default_dna_length = 3
    parts = encoded_str.split(":")
    if len(parts) != default_dna_length:
        e = "Invalid encoded dna format"
        raise ValueError(e)
    encrypted_dna, hash_str, timestamp_str = parts
    return {
        "encrypted_dna": encrypted_dna,
        "hash": hash_str,
        "timestamp": int(timestamp_str),
    }

def encrypt(
    message: str,
    secret_key: str,
    timestamp: int | None,
    ) -> str:
    """Encrypt DNA by blocks with dynamic permutation.

    - message: string to encrypt
    - secret_key: secret key used for dynamic permutation
    - timestamp (optional): timestamp to use, otherwise current timestamp
    Returns a dictionary:
    {
        "encrypted_dna": str,
        "hash": str,
        "timestamp": int
    }
    """
    if timestamp is None:
        timestamp = get_timestamp()

    dna = message_to_dna(message)
    block_size = 8
    if len(dna) % block_size != 0:
        padding_len = block_size - (len(dna) % block_size)
        dna += "A" * padding_len
    blocks = [dna[i:i+block_size] for i in range(0, len(dna), block_size)]

    encrypted_blocks = []
    for i, block in enumerate(blocks):
        seed_str = f"{secret_key}{timestamp}{i}"
        seed_hex = compute_hash(seed_str)
        encrypted_blocks.append(permute_block(block, seed_hex))

    encrypted_dna = "".join(encrypted_blocks)
    hash_str = compute_hash(message + str(timestamp))

    return encode_encrypted_dna(
        encrypted_dna,
        hash_str,
        timestamp,
    )

def decrypt(
    encoded_encrypted_dna: str,
    secret_key: str,
    expected_hash: str | None,
    timestamp_tolerance: int = 300,
    ) -> str:
    """Decrypt DNA + integrity check + timestamp validation.

    - encrypted_dict: dictionary with keys 'encrypted_dna', 'hash', 'timestamp'
    - secret_key: secret key used for dynamic permutation
    - expected_hash (optional): hash to verify, otherwise checks hash in encrypted_dict
    - timestamp_tolerance: tolerance in seconds for timestamp (e.g., 300 = 5 minutes)
    Returns the plaintext message or raises an error if integrity/timestamp check fails.
    """
    encrypted_dict = decode_encrypted_dna(encoded_encrypted_dna)
    encrypted_dna = encrypted_dict["encrypted_dna"]
    hash_str = encrypted_dict.get("hash")
    timestamp = encrypted_dict["timestamp"]

    block_size = 8
    blocks = [
        encrypted_dna[i:i+block_size] for i in range(
            0,
            len(encrypted_dna),
            block_size,
            )
        ]

    decrypted_blocks = []
    for i, block in enumerate(blocks):
        seed_str = f"{secret_key}{timestamp}{i}"
        seed_hex = compute_hash(seed_str)
        decrypted_blocks.append(inverse_permute_block(block, seed_hex))

    decrypted_dna = "".join(decrypted_blocks)
    decrypted_dna = decrypted_dna.rstrip("A")
    message = dna_to_message(decrypted_dna)

    recomputed_hash = compute_hash(message + str(timestamp))
    if expected_hash and expected_hash != recomputed_hash:
        e = "Attended hash does not match recomputed hash"
        raise ValueError(e)
    if hash_str != recomputed_hash:
        e = "Hash in encrypted data does not match recomputed hash"
        raise ValueError(e)

    now = get_timestamp()
    if abs(now - timestamp) > timestamp_tolerance:
        e = f"Timestamp tolerance exceeded: {now} - {timestamp} > {timestamp_tolerance}"
        raise ValueError(e)

    return message
