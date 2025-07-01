# ![encryptool logo](assets/logo_150.png)

An encryption/decryption tool written in Python

## 🛠️ Installation

### 📦 With pip

```bash
pip install encryptool
encryptool --help
```

### 🧬 With sources

```bash
git clone https://github.com/CORT1N/encryptool.git
cd encryptool
python3 -m encryptool --help
```

## ⚙️ Usage examples

### 🔐 Encryption/Decryption

**encryptool** supports 2 ways of encryption.

RSA is the default mode. To use the other, add `-m` followed by 0 for DNA-based

```bash
# It'll by default save the result to output/ciphertext.txt
encryptool e plaintext.txt
```

You can also encrypt from stdin

```bash
encryptool e --stdin <plaintext>
```

Decryption is working the same with `d` flag.

### ✍️ Signature/Verification

You can sign a file when encrypting with `-s`, that will output *output/signature.txt* by default.

If you want to sign it later, you can use `s <cipher-path>`.

To verify a signature, the same logic is applied: `-v --signature-path <sig-path>` when decrypting or `v <cipher-path> --signature <signature-path>`

## 💡 Explanation

❗ Use this project that I created to end a course at ESGI only for educational purposes. Some things may be broken, useless or bad written. ❗

I tried to make the code clear in an object-oriented way with one engine per encryption method.

For RSA, I decided to go with a key generation in the project directory by default to demonstrate it easier, but you can provide it with `--pubkey` and `--privkey`.

Concerning my handmade DNA-based encryption, some key concepts needs to be explained:

### 🧠 Inspiration

**In biology, DNA stores data using four nucleotides: A, C, G and T**. Inspired by this, I encode binary data into DNA-like sequences. Each byte of the original message is mapped to a 4-letter DNA string:

- 00 &rarr; A
- 01 &rarr; C
- 10 &rarr; G
- 11 &rarr; T

For example, the byte **01001100** becomes: 01 00 11 00 &rarr; CAG

### 🔄 Encryption process

1. I convert the message to DNA-like
2. I split the DNA string into 8 letters per block. If needed, it's padded with A to fill the last
3. I swap block. For each, a unique permutation is applied to shuffle the order. This permutation is determined by a seed based on `secret_key + timestamp + block_index` hashed to ensure unpredictability
4. I finally hash it in this format: `encrypted_dna:hash:timestamp:message_length`

### 🔓 Decryption process

1. I parse and validate the encoded string. If the current time is too far from the timestamp (e.g., over 5 minutes), the process fails and the message will never be readable, because it's time based
2. I reconstruct the block using the same deterministic permutation based on the seed
3. I convert the message back to readable characters
4. I check the integrity in recomputing the hash

### 🎯 Design choices

#### Timestamp-based ⏰

The use of timestamp and block index in the permutation seed ensures that encrypting the same message twice gives different results. It adds **non-determinism** and prevents replay attacks.

#### Integrity 🛡️

The hash ensures that the message hasn't been altered. It's also used in decryption to verify both the authenticity and integrity of data.

#### Object-oriented 🧱

Using classes allows extensions and configuration and make the project more modular and testable.

## ⚠️ Known limitations

While the hash helps in authenticity-check process, it doesn't make all.

The project suffers from a lack of signature process like RSA in DNA-based encryption and I know it's a big problem to make it more *production-ready*.
