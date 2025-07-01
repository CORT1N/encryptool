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

def get_permutation(n: int, key_seed: str) -> list[int]:
    """Generate a random permutation of indices based on a key seed."""
    seed_int = int(key_seed, 16)  # No modulo
    random.seed(seed_int)
    indices = list(range(n))
    random.shuffle(indices)
    return indices

def permute_block(block: str, key_seed: str) -> tuple[str, list[int]]:
    """Permute a block of DNA using a key seed."""
    indices = get_permutation(len(block), key_seed)
    permuted = "".join(block[i] for i in indices)
    return permuted, indices

def inverse_permute_block(permuted_block: str, indices: list[int]) -> str:
    """Inverse permute a block of DNA using the original indices."""
    original = [""] * len(permuted_block)
    for i, c in enumerate(permuted_block):
        original[indices[i]] = c
    return "".join(original)

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

def encrypt(
    message: str,
    secret_key: str,
    timestamp: int | None,
) -> str:
    """Encrypt DNA by blocks with dynamic permutation."""
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
        permuted_block, _ = permute_block(block, seed_hex)
        encrypted_blocks.append(permuted_block)

    encrypted_dna = "".join(encrypted_blocks)
    hash_str = compute_hash(message + str(timestamp))
    message_length = len(message)

    return f"{encrypted_dna}:{hash_str}:{timestamp}:{message_length}"

def decrypt(
    encoded_encrypted_dna: str,
    secret_key: str,
    expected_hash: str | None,
    timestamp_tolerance: int = 300,
) -> str:
    """Decrypt DNA + integrity check + timestamp validation."""
    parts = encoded_encrypted_dna.split(":")
    parts_number = 4
    if len(parts) != parts_number:
        e = "Invalid encoded dna format"
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
        seed_str = f"{secret_key}{timestamp}{i}"
        seed_hex = compute_hash(seed_str)
        indices = get_permutation(len(block), seed_hex)  # recreate indices
        decrypted_blocks.append(inverse_permute_block(block, indices))

    decrypted_dna = "".join(decrypted_blocks)

    dna_len = message_length * 4  # Each char = 4 bases
    decrypted_dna = decrypted_dna[:dna_len]
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
