# Stage 14: Cryptography Fundamentals

## Overview

**Duration:** 25-35 hours  
**Difficulty:** Intermediate  
**Prerequisites:** Stage 1-10, Basic mathematics understanding

This stage covers cryptographic concepts essential for cybersecurity professionals. Students will learn how encryption works, common cryptographic algorithms, their vulnerabilities, and how to properly implement and assess cryptographic systems.

---

## Learning Objectives

By the end of this stage, you will be able to:

1. Understand fundamental cryptographic concepts and terminology
2. Differentiate between symmetric and asymmetric encryption
3. Identify common cryptographic algorithms and their use cases
4. Recognize cryptographic vulnerabilities and weaknesses
5. Implement basic cryptographic operations in Python
6. Assess cryptographic implementations for security issues
7. Understand PKI, certificates, and TLS/SSL

---

## Module 14.1: Cryptography Basics (4-5 hours)

### 14.1.1 Core Concepts

```
CRYPTOGRAPHY TERMINOLOGY:
═════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   PLAINTEXT ──────▶ ENCRYPTION ──────▶ CIPHERTEXT                       │
│       │                  │                  │                           │
│       │                  │                  │                           │
│       ▼                  ▼                  ▼                           │
│   Original           Algorithm +        Encrypted                       │
│   readable           Key(s)             unreadable                      │
│   message                               message                         │
│                                                                         │
│   CIPHERTEXT ──────▶ DECRYPTION ──────▶ PLAINTEXT                       │
│                          │                                              │
│                          ▼                                              │
│                      Algorithm +                                        │
│                      Key(s)                                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

KEY TERMS:
──────────
• Plaintext   - Original unencrypted data
• Ciphertext  - Encrypted data
• Encryption  - Process of converting plaintext to ciphertext
• Decryption  - Process of converting ciphertext to plaintext
• Key         - Secret value used in encryption/decryption
• Algorithm   - Mathematical procedure for encryption
• Cipher      - The algorithm used for encryption

CRYPTOGRAPHIC GOALS:
────────────────────
• Confidentiality - Only authorized parties can read data
• Integrity       - Data has not been modified
• Authentication  - Verify identity of sender
• Non-repudiation - Sender cannot deny sending message
```

### 14.1.2 Types of Cryptography

```
CRYPTOGRAPHY TYPES:
═══════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                     SYMMETRIC CRYPTOGRAPHY                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐        Same Key         ┌─────────┐                       │
│   │  Alice  │◄───────────────────────▶│   Bob   │                       │
│   └─────────┘         🔑              └─────────┘                       │
│                                                                         │
│   • Same key for encryption and decryption                              │
│   • Fast and efficient                                                  │
│   • Key distribution problem                                            │
│   • Examples: AES, DES, 3DES, ChaCha20                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    ASYMMETRIC CRYPTOGRAPHY                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐                         ┌─────────┐                       │
│   │  Alice  │                         │   Bob   │                       │
│   │ 🔑 🔓  │                         │ 🔑 🔓  │                       │
│   │Priv Pub │                         │Priv Pub │                       │
│   └─────────┘                         └─────────┘                       │
│                                                                         │
│   Alice encrypts with Bob's PUBLIC key                                  │
│   Bob decrypts with his PRIVATE key                                     │
│                                                                         │
│   • Key pair: public key + private key                                  │
│   • Slower than symmetric                                               │
│   • Solves key distribution                                             │
│   • Examples: RSA, ECC, DSA, DH                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                       HASH FUNCTIONS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Input (any size) ──────▶ Hash Function ──────▶ Fixed-size output      │
│                                                                         │
│   "Hello" ──────▶ SHA-256 ──────▶ 2cf24dba5fb0a30e26e83b2ac5b9e29...    │
│                                                                         │
│   Properties:                                                           │
│   • One-way (cannot reverse)                                            │
│   • Deterministic (same input = same output)                            │
│   • Collision resistant                                                 │
│   • Avalanche effect (small change = big difference)                    │
│   • Examples: SHA-256, SHA-3, BLAKE2, MD5 (broken)                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 14.1.3 Classical Ciphers (Historical)

```python
#!/usr/bin/env python3
"""
classical_ciphers.py - Historical cipher implementations (educational)
"""

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    """
    Caesar Cipher - shifts letters by fixed amount
    Used by Julius Caesar (100-44 BC)
    BROKEN: Only 25 possible keys, trivial to brute force
    """
    if decrypt:
        shift = -shift
    
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    
    return ''.join(result)


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    """
    Vigenère Cipher - polyalphabetic substitution
    Uses a keyword to determine shift for each letter
    BROKEN: Vulnerable to frequency analysis (Kasiski examination)
    """
    result = []
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if decrypt:
                shift = -shift
            
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def xor_cipher(data: bytes, key: bytes) -> bytes:
    """
    XOR Cipher - foundation of modern stream ciphers
    
    Properties:
    - A XOR B XOR B = A (self-inverse)
    - Used in one-time pad (unbreakable if key is random and never reused)
    
    BROKEN if: key is reused, key is shorter than message
    """
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


# Demonstration
if __name__ == "__main__":
    print("=== Classical Ciphers (Educational) ===\n")
    
    # Caesar
    plaintext = "HELLO WORLD"
    encrypted = caesar_cipher(plaintext, 3)
    decrypted = caesar_cipher(encrypted, 3, decrypt=True)
    print(f"Caesar Cipher (shift=3):")
    print(f"  Plaintext:  {plaintext}")
    print(f"  Encrypted:  {encrypted}")
    print(f"  Decrypted:  {decrypted}\n")
    
    # Vigenère
    plaintext = "ATTACKATDAWN"
    key = "LEMON"
    encrypted = vigenere_cipher(plaintext, key)
    decrypted = vigenere_cipher(encrypted, key, decrypt=True)
    print(f"Vigenère Cipher (key='{key}'):")
    print(f"  Plaintext:  {plaintext}")
    print(f"  Encrypted:  {encrypted}")
    print(f"  Decrypted:  {decrypted}\n")
```

---

## Module 14.2: Symmetric Encryption (5-6 hours)

### 14.2.1 Block Ciphers

```
BLOCK CIPHER MODES:
═══════════════════

ECB (Electronic Codebook) - DO NOT USE
──────────────────────────────────────
• Each block encrypted independently
• Same plaintext block = same ciphertext block
• Patterns visible in ciphertext
• INSECURE for most purposes

    P1 ──▶ [E] ──▶ C1
    P2 ──▶ [E] ──▶ C2    (if P1 = P2, then C1 = C2!)
    P3 ──▶ [E] ──▶ C3


CBC (Cipher Block Chaining) - Common but has issues
───────────────────────────────────────────────────
• Each block XORed with previous ciphertext
• Requires Initialization Vector (IV)
• IV must be random and unpredictable
• Vulnerable to padding oracle attacks

    IV ──┐
         ▼
    P1 ─▶[XOR]──▶[E]──▶ C1 ──┐
                              ▼
    P2 ─────────▶[XOR]──▶[E]──▶ C2


CTR (Counter Mode) - Recommended
────────────────────────────────
• Turns block cipher into stream cipher
• Parallelizable
• No padding required
• Requires unique nonce per key

    Nonce+0 ──▶[E]──▶[XOR]◀── P1 ──▶ C1
    Nonce+1 ──▶[E]──▶[XOR]◀── P2 ──▶ C2


GCM (Galois/Counter Mode) - RECOMMENDED
───────────────────────────────────────
• CTR mode + authentication
• Provides confidentiality AND integrity
• AEAD (Authenticated Encryption with Associated Data)
• Standard for TLS 1.3

    CTR encryption + GHASH authentication = Ciphertext + Tag
```

### 14.2.2 AES (Advanced Encryption Standard)

```python
#!/usr/bin/env python3
"""
aes_examples.py - AES encryption examples
Requires: pip install cryptography
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

def aes_cbc_example():
    """
    AES-CBC encryption (with proper IV handling)
    Note: For production, use AES-GCM instead
    """
    print("=== AES-CBC Example ===")
    
    # Generate random key and IV
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV (must be random for each encryption)
    
    # Plaintext (must be multiple of 16 bytes for CBC)
    plaintext = b"This is a secret message!!!!!"  # 30 bytes, needs padding
    
    # PKCS7 padding
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length]
    
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")


def aes_gcm_example():
    """
    AES-GCM - RECOMMENDED for most use cases
    Provides both encryption and authentication
    """
    print("\n=== AES-GCM Example (RECOMMENDED) ===")
    
    # Generate random key and nonce
    key = os.urandom(32)   # 256-bit key
    nonce = os.urandom(12) # 96-bit nonce (standard for GCM)
    
    # Associated data (authenticated but not encrypted)
    associated_data = b"header information"
    
    # Plaintext
    plaintext = b"This is a secret message!"
    
    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Decrypt
    decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    print(f"Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext + Tag: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")


# Common AES mistakes to avoid
AES_COMMON_MISTAKES = """
COMMON AES IMPLEMENTATION MISTAKES:
═══════════════════════════════════

1. ECB MODE
   ─────────
   WRONG: cipher = AES.new(key, AES.MODE_ECB)
   RIGHT: Use GCM or CBC with random IV

2. FIXED/PREDICTABLE IV
   ─────────────────────
   WRONG: iv = b'0000000000000000'
   RIGHT: iv = os.urandom(16)

3. REUSING NONCE IN GCM
   ─────────────────────
   Reusing nonce with same key completely breaks GCM security
   MUST use unique nonce for each encryption

4. WEAK KEYS
   ──────────
   WRONG: key = b'password12345678'
   RIGHT: key = os.urandom(32)  # or derive with PBKDF2

5. NO AUTHENTICATION
   ──────────────────
   WRONG: CBC without HMAC
   RIGHT: Use AES-GCM or add HMAC

6. IMPROPER PADDING
   ─────────────────
   Always use PKCS7 padding
   Validate padding on decryption (padding oracle!)
"""

if __name__ == "__main__":
    aes_cbc_example()
    aes_gcm_example()
    print(AES_COMMON_MISTAKES)
```

---

## Module 14.3: Asymmetric Encryption (5-6 hours)

### 14.3.1 RSA

```python
#!/usr/bin/env python3
"""
rsa_examples.py - RSA encryption and signing examples
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

RSA_OVERVIEW = """
RSA (Rivest-Shamir-Adleman):
════════════════════════════

KEY GENERATION:
───────────────
1. Choose two large prime numbers: p, q
2. Compute n = p × q (modulus)
3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
4. Choose e (public exponent, commonly 65537)
5. Compute d where (d × e) mod φ(n) = 1 (private exponent)

Public Key:  (n, e)
Private Key: (n, d)

ENCRYPTION:
───────────
Ciphertext = Plaintext^e mod n

DECRYPTION:
───────────
Plaintext = Ciphertext^d mod n

SECURITY:
─────────
• Based on difficulty of factoring large numbers
• Key sizes: 2048-bit minimum, 4096-bit recommended
• Slower than symmetric encryption
• Usually encrypts symmetric keys, not data directly
"""


def rsa_key_generation():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encryption_example():
    """RSA encryption (use for key exchange, not bulk data)"""
    print("=== RSA Encryption Example ===")
    
    # Generate keys
    private_key, public_key = rsa_key_generation()
    
    # Encrypt with public key (OAEP padding - recommended)
    message = b"Secret symmetric key"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt with private key
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Message: {message}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Decrypted: {decrypted}")


def rsa_signature_example():
    """RSA digital signature"""
    print("\n=== RSA Signature Example ===")
    
    private_key, public_key = rsa_key_generation()
    
    # Sign with private key
    message = b"This message is authentic"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Verify with public key
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"Message: {message}")
        print(f"Signature valid: True")
    except Exception as e:
        print(f"Signature valid: False - {e}")


RSA_VULNERABILITIES = """
RSA VULNERABILITIES AND ATTACKS:
════════════════════════════════

1. SMALL KEY SIZE
   ───────────────
   • Keys < 1024 bits can be factored
   • Use 2048-bit minimum, 4096-bit preferred

2. WEAK PADDING (PKCS#1 v1.5)
   ──────────────────────────
   • Vulnerable to Bleichenbacher attack
   • Use OAEP padding for encryption
   • Use PSS padding for signatures

3. SMALL EXPONENT ATTACKS
   ───────────────────────
   • If e is small and message is small
   • Always use proper padding

4. COMMON MODULUS ATTACK
   ──────────────────────
   • Never share modulus between key pairs

5. TIMING ATTACKS
   ───────────────
   • Implementation must use constant-time operations
"""

if __name__ == "__main__":
    print(RSA_OVERVIEW)
    rsa_encryption_example()
    rsa_signature_example()
    print(RSA_VULNERABILITIES)
```

### 14.3.2 Elliptic Curve Cryptography (ECC)

```python
#!/usr/bin/env python3
"""
ecc_examples.py - Elliptic Curve Cryptography examples
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

ECC_OVERVIEW = """
ELLIPTIC CURVE CRYPTOGRAPHY (ECC):
══════════════════════════════════

ADVANTAGES OVER RSA:
────────────────────
• Smaller key sizes for equivalent security
• Faster key generation
• Faster signing operations
• Lower computational overhead

KEY SIZE COMPARISON:
────────────────────
┌─────────────────────────────────────────────┐
│ Security Level │    RSA    │     ECC       │
├────────────────┼───────────┼───────────────┤
│    80 bits     │  1024-bit │   160-bit     │
│   112 bits     │  2048-bit │   224-bit     │
│   128 bits     │  3072-bit │   256-bit     │
│   192 bits     │  7680-bit │   384-bit     │
│   256 bits     │ 15360-bit │   512-bit     │
└─────────────────────────────────────────────┘

COMMON CURVES:
──────────────
• P-256 (secp256r1)  - NIST, widely supported
• P-384 (secp384r1)  - Higher security
• P-521 (secp521r1)  - Highest NIST security
• Curve25519         - Modern, fast, safe
• secp256k1          - Used by Bitcoin
"""


def ecdh_key_exchange():
    """Elliptic Curve Diffie-Hellman key exchange"""
    print("=== ECDH Key Exchange ===")
    
    # Alice generates key pair
    alice_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    alice_public = alice_private.public_key()
    
    # Bob generates key pair
    bob_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_public = bob_private.public_key()
    
    # Key exchange
    alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
    bob_shared = bob_private.exchange(ec.ECDH(), alice_public)
    
    # Derive symmetric key from shared secret
    alice_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(alice_shared)
    
    bob_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(bob_shared)
    
    print(f"Shared secrets match: {alice_key == bob_key}")
    print(f"Derived symmetric key: {alice_key.hex()}")


def ecdsa_signature():
    """Elliptic Curve Digital Signature Algorithm"""
    print("\n=== ECDSA Signature ===")
    
    # Generate key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    # Sign message
    message = b"Authenticate this message"
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Verify signature
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print(f"Message: {message}")
        print(f"Signature length: {len(signature)} bytes")
        print("Signature valid: True")
    except Exception as e:
        print(f"Signature valid: False - {e}")


if __name__ == "__main__":
    print(ECC_OVERVIEW)
    ecdh_key_exchange()
    ecdsa_signature()
```

---

## Module 14.4: Hash Functions and MACs (4-5 hours)

### 14.4.1 Cryptographic Hash Functions

```python
#!/usr/bin/env python3
"""
hash_functions.py - Cryptographic hash function examples
"""

import hashlib
import hmac
import os

HASH_OVERVIEW = """
CRYPTOGRAPHIC HASH FUNCTIONS:
═════════════════════════════

PROPERTIES:
───────────
• Deterministic: Same input always produces same output
• Fixed output: Regardless of input size
• Fast: Quick to compute
• Pre-image resistant: Can't find input from output
• Second pre-image resistant: Can't find another input with same hash
• Collision resistant: Can't find two inputs with same hash
• Avalanche effect: Small change = completely different hash

HASH FUNCTION STATUS:
─────────────────────
┌─────────────────────────────────────────────────────────────────┐
│ Algorithm │ Output Size │ Status        │ Use Cases             │
├───────────┼─────────────┼───────────────┼───────────────────────┤
│ MD5       │ 128 bits    │ BROKEN        │ Checksums only        │
│ SHA-1     │ 160 bits    │ BROKEN        │ Legacy only           │
│ SHA-256   │ 256 bits    │ SECURE        │ General purpose       │
│ SHA-384   │ 384 bits    │ SECURE        │ High security         │
│ SHA-512   │ 512 bits    │ SECURE        │ High security         │
│ SHA-3     │ Variable    │ SECURE        │ Alternative to SHA-2  │
│ BLAKE2    │ Variable    │ SECURE        │ Fast, modern          │
│ BLAKE3    │ 256 bits    │ SECURE        │ Very fast, modern     │
└─────────────────────────────────────────────────────────────────┘
"""


def hash_examples():
    """Demonstrate various hash functions"""
    print("=== Hash Function Examples ===\n")
    
    message = b"The quick brown fox jumps over the lazy dog"
    
    # MD5 (BROKEN - for comparison only)
    md5_hash = hashlib.md5(message).hexdigest()
    print(f"MD5 (BROKEN):    {md5_hash}")
    
    # SHA-1 (BROKEN - for comparison only)
    sha1_hash = hashlib.sha1(message).hexdigest()
    print(f"SHA-1 (BROKEN):  {sha1_hash}")
    
    # SHA-256 (RECOMMENDED)
    sha256_hash = hashlib.sha256(message).hexdigest()
    print(f"SHA-256:         {sha256_hash}")
    
    # SHA-512
    sha512_hash = hashlib.sha512(message).hexdigest()
    print(f"SHA-512:         {sha512_hash}")
    
    # SHA-3
    sha3_256_hash = hashlib.sha3_256(message).hexdigest()
    print(f"SHA3-256:        {sha3_256_hash}")
    
    # BLAKE2
    blake2_hash = hashlib.blake2b(message).hexdigest()
    print(f"BLAKE2b:         {blake2_hash}")


def avalanche_effect_demo():
    """Demonstrate avalanche effect"""
    print("\n=== Avalanche Effect Demo ===")
    
    msg1 = b"Hello World"
    msg2 = b"Hello World!"  # Just added !
    
    hash1 = hashlib.sha256(msg1).hexdigest()
    hash2 = hashlib.sha256(msg2).hexdigest()
    
    # Count differing bits
    bits_different = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
    
    print(f"Message 1: {msg1}")
    print(f"Hash 1:    {hash1}")
    print(f"Message 2: {msg2}")
    print(f"Hash 2:    {hash2}")
    print(f"Bits different: {bits_different} out of 256 ({bits_different/256*100:.1f}%)")


if __name__ == "__main__":
    print(HASH_OVERVIEW)
    hash_examples()
    avalanche_effect_demo()
```

### 14.4.2 Message Authentication Codes (MACs)

```python
#!/usr/bin/env python3
"""
mac_examples.py - Message Authentication Code examples
"""

import hmac
import hashlib
import os

MAC_OVERVIEW = """
MESSAGE AUTHENTICATION CODES (MACs):
════════════════════════════════════

PURPOSE:
────────
• Verify message integrity
• Verify message authenticity
• Requires shared secret key

TYPES:
──────
1. HMAC (Hash-based MAC)
   • Uses hash function with key
   • HMAC-SHA256, HMAC-SHA384, HMAC-SHA512

2. CMAC (Cipher-based MAC)
   • Uses block cipher (AES-CMAC)

3. Poly1305
   • Used with ChaCha20
   • Very fast

HMAC CONSTRUCTION:
──────────────────
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

Where:
• K = secret key
• H = hash function
• opad = outer padding (0x5c5c...)
• ipad = inner padding (0x3636...)
"""


def hmac_example():
    """HMAC-SHA256 example"""
    print("=== HMAC Example ===")
    
    # Shared secret key
    key = os.urandom(32)
    
    # Message to authenticate
    message = b"This message is authenticated"
    
    # Create HMAC
    mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    print(f"Key: {key.hex()}")
    print(f"Message: {message}")
    print(f"HMAC-SHA256: {mac}")
    
    # Verify HMAC
    received_mac = mac
    expected_mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    # Use constant-time comparison to prevent timing attacks
    is_valid = hmac.compare_digest(received_mac, expected_mac)
    print(f"MAC valid: {is_valid}")


def mac_vs_hash():
    """Demonstrate why MAC is needed, not just hash"""
    print("\n=== MAC vs Hash ===")
    
    print("""
    PROBLEM WITH JUST HASHING:
    ──────────────────────────
    
    Hash(message) -> anyone can compute
    
    Attacker can:
    1. Intercept message
    2. Modify message
    3. Compute new hash
    4. Send modified message + new hash
    
    WITH MAC:
    ─────────
    
    HMAC(key, message) -> only key holder can compute
    
    Attacker cannot:
    1. Compute valid MAC without key
    2. Modify message undetected
    """)


HMAC_BEST_PRACTICES = """
HMAC BEST PRACTICES:
════════════════════

1. KEY GENERATION
   ───────────────
   • Use cryptographically random key
   • Key should be at least as long as hash output
   • 256 bits (32 bytes) for HMAC-SHA256

2. KEY STORAGE
   ────────────
   • Never hardcode keys
   • Use secure key storage (HSM, KMS)
   • Rotate keys periodically

3. VERIFICATION
   ─────────────
   • Always use constant-time comparison
   • hmac.compare_digest() in Python
   • Never use == for MAC comparison (timing attack!)

4. ALGORITHM CHOICE
   ─────────────────
   • HMAC-SHA256 for general use
   • HMAC-SHA512 for higher security
   • Avoid HMAC-MD5 and HMAC-SHA1
"""

if __name__ == "__main__":
    print(MAC_OVERVIEW)
    hmac_example()
    mac_vs_hash()
    print(HMAC_BEST_PRACTICES)
```

---

## Module 14.5: PKI and Certificates (4-5 hours)

### 14.5.1 Public Key Infrastructure

```
PKI (PUBLIC KEY INFRASTRUCTURE):
════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                          PKI HIERARCHY                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                    ┌─────────────────────┐                              │
│                    │    Root CA          │                              │
│                    │  (Self-signed)      │                              │
│                    │  Offline/Air-gapped │                              │
│                    └──────────┬──────────┘                              │
│                               │                                         │
│              ┌────────────────┼────────────────┐                        │
│              │                │                │                        │
│      ┌───────▼───────┐ ┌──────▼──────┐ ┌──────▼──────┐                  │
│      │ Intermediate  │ │ Intermediate│ │ Intermediate│                  │
│      │     CA 1      │ │    CA 2     │ │    CA 3     │                  │
│      └───────┬───────┘ └──────┬──────┘ └─────────────┘                  │
│              │                │                                         │
│      ┌───────▼───────┐ ┌──────▼──────┐                                  │
│      │  End Entity   │ │ End Entity  │                                  │
│      │  Certificate  │ │ Certificate │                                  │
│      │ (website.com) │ │ (user cert) │                                  │
│      └───────────────┘ └─────────────┘                                  │
│                                                                         │
│   COMPONENTS:                                                           │
│   ───────────                                                           │
│   • Certificate Authority (CA) - Issues and signs certificates          │
│   • Registration Authority (RA) - Verifies identity                     │
│   • Certificate Store - Trusted root certificates                       │
│   • Certificate Revocation List (CRL) - Revoked certificates            │
│   • OCSP - Online Certificate Status Protocol                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 14.5.2 X.509 Certificates

```python
#!/usr/bin/env python3
"""
certificate_examples.py - X.509 certificate analysis
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

X509_OVERVIEW = """
X.509 CERTIFICATE STRUCTURE:
════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                       X.509 CERTIFICATE                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Version: 3 (v3)                                                       │
│   Serial Number: Unique identifier                                      │
│   Signature Algorithm: sha256WithRSAEncryption                          │
│                                                                         │
│   Issuer:                                                               │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ CN=Example CA, O=Example Inc, C=US                              │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Validity:                                                             │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Not Before: Jan 1, 2024                                         │   │
│   │ Not After:  Jan 1, 2025                                         │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Subject:                                                              │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ CN=www.example.com, O=Example Inc, C=US                         │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Subject Public Key Info:                                              │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Algorithm: RSA                                                  │   │
│   │ Key Size: 2048 bits                                             │   │
│   │ Public Key: [...]                                               │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Extensions:                                                           │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Subject Alternative Name: www.example.com, example.com          │   │
│   │ Key Usage: Digital Signature, Key Encipherment                  │   │
│   │ Extended Key Usage: TLS Web Server Authentication               │   │
│   │ Basic Constraints: CA:FALSE                                     │   │
│   │ Authority Key Identifier: [...]                                 │   │
│   │ Subject Key Identifier: [...]                                   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   Signature:                                                            │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ [CA's signature over certificate data]                          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
"""


def generate_self_signed_cert():
    """Generate a self-signed certificate (for testing)"""
    print("=== Generating Self-Signed Certificate ===")
    
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
    ])
    
    # Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("www.example.com"),
                x509.DNSName("example.com"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Serial: {cert.serial_number}")
    print(f"Valid from: {cert.not_valid_before}")
    print(f"Valid until: {cert.not_valid_after}")
    
    return cert, private_key


CERTIFICATE_SECURITY = """
CERTIFICATE SECURITY CONSIDERATIONS:
════════════════════════════════════

VULNERABILITIES:
────────────────
• Weak signature algorithm (MD5, SHA-1)
• Short key length (< 2048 bits for RSA)
• Long validity periods
• Missing revocation checking
• Wildcard certificate misuse
• Certificate pinning bypass

BEST PRACTICES:
───────────────
• Use SHA-256 or stronger signatures
• RSA 2048+ or ECC P-256+
• Short validity (1 year max)
• Implement OCSP stapling
• Use Certificate Transparency
• Consider certificate pinning for mobile apps

TOOLS FOR ANALYSIS:
───────────────────
• openssl x509 -in cert.pem -text
• SSLLabs SSL Test
• testssl.sh
"""

if __name__ == "__main__":
    print(X509_OVERVIEW)
    generate_self_signed_cert()
    print(CERTIFICATE_SECURITY)
```

---

## Module 14.6: TLS/SSL Security (4-5 hours)

### 14.6.1 TLS Handshake

```
TLS 1.3 HANDSHAKE:
══════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   Client                                            Server              │
│     │                                                  │                │
│     │ ─────────── ClientHello ────────────────────▶   │                │
│     │   • Supported cipher suites                      │                │
│     │   • Key share (ECDHE)                            │                │
│     │   • Random                                       │                │
│     │                                                  │                │
│     │ ◀────────── ServerHello ─────────────────────   │                │
│     │   • Selected cipher suite                        │                │
│     │   • Key share (ECDHE)                            │                │
│     │   • Random                                       │                │
│     │                                                  │                │
│     │ ◀─────── EncryptedExtensions ────────────────   │                │
│     │ ◀─────── Certificate ────────────────────────   │                │
│     │ ◀─────── CertificateVerify ──────────────────   │                │
│     │ ◀─────── Finished ───────────────────────────   │                │
│     │                                                  │                │
│     │ ─────────── Finished ────────────────────────▶   │                │
│     │                                                  │                │
│     │ ◀═══════ Application Data ═══════════════════▶  │                │
│     │                                                  │                │
│                                                                         │
│   • 1-RTT handshake (vs 2-RTT in TLS 1.2)                               │
│   • Forward secrecy mandatory                                           │
│   • Only AEAD ciphers allowed                                           │
│   • Removed legacy algorithms                                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 14.6.2 TLS Security Assessment

```python
#!/usr/bin/env python3
"""
tls_assessment.py - TLS/SSL security checking concepts
"""

TLS_VULNERABILITIES = """
TLS/SSL VULNERABILITIES:
════════════════════════

PROTOCOL VULNERABILITIES:
─────────────────────────

1. SSL 2.0 / SSL 3.0
   • COMPLETELY BROKEN
   • Disable immediately
   • POODLE attack on SSL 3.0

2. TLS 1.0 / TLS 1.1
   • DEPRECATED
   • BEAST attack (TLS 1.0)
   • Should be disabled

3. TLS 1.2
   • Still secure if properly configured
   • Avoid weak cipher suites
   • Use AEAD ciphers (GCM, ChaCha20-Poly1305)

4. TLS 1.3
   • RECOMMENDED
   • Removed weak algorithms
   • Forward secrecy mandatory

CIPHER SUITE ISSUES:
────────────────────

AVOID:
• NULL ciphers (no encryption)
• EXPORT ciphers (weak - FREAK attack)
• DES/3DES (SWEET32 attack)
• RC4 (bias attacks)
• MD5/SHA1 for signatures
• Static RSA key exchange (no PFS)

RECOMMENDED:
• TLS_AES_256_GCM_SHA384 (TLS 1.3)
• TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
• ECDHE-ECDSA-AES256-GCM-SHA384 (TLS 1.2)
• ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)

NOTABLE ATTACKS:
────────────────
• BEAST - Browser Exploit Against SSL/TLS (CBC IV)
• CRIME/BREACH - Compression side channel
• Heartbleed - OpenSSL buffer over-read
• POODLE - Padding Oracle On Downgraded Legacy Encryption
• DROWN - Decrypting RSA with Obsolete and Weakened eNcryption
• ROBOT - Return Of Bleichenbacher's Oracle Threat
"""

TLS_TESTING = """
TLS TESTING COMMANDS:
═════════════════════

OPENSSL:
────────
# Check TLS connection
openssl s_client -connect example.com:443 -tls1_3

# Show certificate
openssl s_client -connect example.com:443 -showcerts

# Test specific protocol
openssl s_client -connect example.com:443 -ssl3  # Should fail
openssl s_client -connect example.com:443 -tls1  # Should fail

NMAP:
─────
# Enumerate ciphers
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for vulnerabilities
nmap --script ssl-heartbleed -p 443 example.com

TESTSSL.SH:
───────────
# Comprehensive test
./testssl.sh example.com

SSLYZE:
───────
# Python-based scanner
sslyze --regular example.com:443
"""

SECURE_CONFIG = """
SECURE TLS CONFIGURATION:
═════════════════════════

NGINX EXAMPLE:
──────────────
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000" always;

APACHE EXAMPLE:
───────────────
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder off
Header always set Strict-Transport-Security "max-age=63072000"
"""

print(TLS_VULNERABILITIES)
print(TLS_TESTING)
print(SECURE_CONFIG)
```

---

## Module 14.7: Cryptographic Attacks (3-4 hours)

### 14.7.1 Common Cryptographic Attacks

```python
#!/usr/bin/env python3
"""
crypto_attacks.py - Common cryptographic attacks overview
"""

CRYPTO_ATTACKS = """
CRYPTOGRAPHIC ATTACK CATEGORIES:
════════════════════════════════

1. BRUTE FORCE ATTACKS
   ────────────────────
   • Try all possible keys
   • Mitigated by long keys
   • DES 56-bit: feasible
   • AES 128-bit: infeasible

2. DICTIONARY ATTACKS
   ───────────────────
   • Try common passwords
   • Effective against weak passwords
   • Mitigated by strong key derivation

3. FREQUENCY ANALYSIS
   ───────────────────
   • Analyze character/pattern frequency
   • Effective against simple substitution
   • Modern ciphers are immune

4. KNOWN PLAINTEXT ATTACK
   ───────────────────────
   • Attacker has plaintext-ciphertext pairs
   • May reveal key or patterns
   • Modern ciphers resist this

5. CHOSEN PLAINTEXT ATTACK
   ────────────────────────
   • Attacker can encrypt chosen messages
   • More powerful than known plaintext
   • CPA security is standard requirement

6. CHOSEN CIPHERTEXT ATTACK
   ─────────────────────────
   • Attacker can decrypt chosen ciphertexts
   • Most powerful oracle attack
   • Padding oracle is an example

7. SIDE CHANNEL ATTACKS
   ─────────────────────
   • Timing attacks
   • Power analysis
   • Electromagnetic emissions
   • Cache attacks
   • Acoustic analysis

8. IMPLEMENTATION ATTACKS
   ───────────────────────
   • Padding oracle
   • Bleichenbacher attack
   • Key reuse issues
   • IV reuse in CTR/GCM
"""

PADDING_ORACLE = """
PADDING ORACLE ATTACK:
══════════════════════

CONCEPT:
────────
• Exploits servers that reveal padding validity
• Works against CBC mode with PKCS7 padding
• Can decrypt ciphertext byte-by-byte

ATTACK FLOW:
────────────
1. Send modified ciphertext to server
2. Server decrypts and checks padding
3. Server returns different error for:
   - Invalid padding
   - Valid padding but invalid data
4. Attacker learns if padding is valid
5. Uses XOR properties to decrypt

MITIGATION:
───────────
• Use authenticated encryption (AES-GCM)
• Don't reveal padding errors
• Encrypt-then-MAC
• Constant-time operations
"""

IV_REUSE = """
IV/NONCE REUSE ATTACKS:
═══════════════════════

CTR MODE IV REUSE:
──────────────────
• C1 = P1 XOR keystream
• C2 = P2 XOR keystream (same keystream!)
• C1 XOR C2 = P1 XOR P2
• If P1 is known, P2 is revealed

GCM NONCE REUSE:
────────────────
• Completely breaks authentication
• Can forge messages
• Recover authentication key

STREAM CIPHER KEY REUSE:
────────────────────────
• Same as CTR IV reuse
• WEP vulnerability (key + IV reuse)

MITIGATION:
───────────
• Use random IV/nonce
• Counter-based nonce generation
• Never reuse with same key
"""

print(CRYPTO_ATTACKS)
print(PADDING_ORACLE)
print(IV_REUSE)
```

---

## Module 14.8: Hands-On Labs (3-4 hours)

### Lab 14.1: Encryption Implementation

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   LAB 14.1: ENCRYPTION IMPLEMENTATION                    ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Implement secure encryption and identify common mistakes     ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Implement AES-GCM encryption/decryption                              ║
║  2. Implement RSA encryption with OAEP padding                           ║
║  3. Create hybrid encryption system                                      ║
║  4. Identify vulnerabilities in provided code samples                    ║
║                                                                          ║
║  REQUIREMENTS:                                                           ║
║  • Python with cryptography library                                      ║
║  • pip install cryptography                                              ║
║                                                                          ║
║  DELIVERABLES:                                                           ║
║  • Working encryption module                                             ║
║  • Test cases demonstrating security                                     ║
║  • Report on common implementation mistakes                              ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Lab 14.2: TLS Assessment

```
╔══════════════════════════════════════════════════════════════════════════╗
║                      LAB 14.2: TLS ASSESSMENT                            ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Assess TLS configuration of web servers                      ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Use OpenSSL to enumerate cipher suites                               ║
║  2. Use testssl.sh for comprehensive assessment                          ║
║  3. Identify weak configurations                                         ║
║  4. Provide remediation recommendations                                  ║
║                                                                          ║
║  COMMANDS:                                                               ║
║  openssl s_client -connect target:443                                    ║
║  nmap --script ssl-enum-ciphers -p 443 target                            ║
║  ./testssl.sh target                                                     ║
║                                                                          ║
║  DELIVERABLES:                                                           ║
║  • TLS assessment report                                                 ║
║  • Vulnerability findings                                                ║
║  • Secure configuration recommendations                                  ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Summary and Key Takeaways

### Algorithm Recommendations

| Use Case | Recommended | Avoid |
|----------|-------------|-------|
| Symmetric Encryption | AES-256-GCM | DES, 3DES, RC4, ECB mode |
| Asymmetric Encryption | RSA-2048+, ECC P-256+ | RSA-1024, PKCS#1 v1.5 |
| Hashing | SHA-256, SHA-3, BLAKE2 | MD5, SHA-1 |
| MAC | HMAC-SHA256 | HMAC-MD5, HMAC-SHA1 |
| Key Exchange | ECDHE, X25519 | Static RSA, DH-1024 |
| TLS | TLS 1.3, TLS 1.2 with AEAD | SSL, TLS 1.0, TLS 1.1 |

### Common Mistakes to Avoid

1. ECB mode for encryption
2. Hardcoded or weak keys
3. IV/nonce reuse
4. Missing authentication (use AEAD)
5. Weak password hashing (use Argon2, bcrypt)
6. Timing-vulnerable comparisons

---

## Further Reading

- Applied Cryptography (Bruce Schneier)
- Cryptography Engineering (Ferguson, Schneier, Kohno)
- Serious Cryptography (Jean-Philippe Aumasson)
- NIST Cryptographic Standards
- https://cryptopals.com/ (Practical exercises)

---

*Stage 14 Complete - Continue to Stage 15: Malware Analysis*
