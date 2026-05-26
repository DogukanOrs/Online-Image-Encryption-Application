"""
DES (Data Encryption Standard) — pure-Python implementation.

Features
--------
* All standard permutation / substitution tables (IP, FP, E, P, S1-S8, PC1, PC2).
* 16-round Feistel network.
* Key schedule producing 16 × 48-bit round keys from a 64-bit (8-byte) key.
* ECB mode with PKCS5 padding for arbitrary-length data.

Public API
----------
    generate_round_keys(key)          -> list[int]   (16 round keys)
    des_encrypt_block(block, round_keys) -> bytes     (single 8-byte block)
    des_decrypt_block(block, round_keys) -> bytes     (single 8-byte block)
    des_encrypt(plaintext_bytes, key) -> bytes         (ECB + PKCS5 pad)
    des_decrypt(ciphertext_bytes, key) -> bytes        (ECB + PKCS5 unpad)
"""

# ---------------------------------------------------------------------------
#  Standard DES tables  (all 1-indexed as per the FIPS 46-3 specification)
# ---------------------------------------------------------------------------

# Initial Permutation (IP) — applied to the 64-bit plaintext block
IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# Final Permutation (FP = IP⁻¹)
FP = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# Expansion permutation (E) — expands 32-bit half-block to 48 bits
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Permutation (P) — applied after S-box substitution
P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# Eight S-boxes (each 4 rows × 16 columns)
S_BOXES = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6,  2,  0, 14,  9, 11],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]

# Permuted Choice 1 (PC-1) — selects 56 bits from the 64-bit key (drops parity)
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# Permuted Choice 2 (PC-2) — selects 48 bits from the 56-bit combined C+D
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Left-shift schedule for the 16 rounds of the key schedule
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ---------------------------------------------------------------------------
#  Helper utilities
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list[int]:
    """Convert a bytes object to a list of bits (MSB first per byte)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Convert a list of bits back to a bytes object (MSB first per byte)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def _permute(bits: list[int], table: list[int]) -> list[int]:
    """Apply a permutation table to a list of bits.

    Tables are 1-indexed (as in the FIPS spec), so we subtract 1.
    """
    return [bits[pos - 1] for pos in table]


def _left_rotate(bits: list[int], n: int) -> list[int]:
    """Left-circular-rotate a list of bits by *n* positions."""
    return bits[n:] + bits[:n]


def _xor(a: list[int], b: list[int]) -> list[int]:
    """Bitwise XOR of two equal-length bit lists."""
    return [x ^ y for x, y in zip(a, b)]


# ---------------------------------------------------------------------------
#  Key schedule
# ---------------------------------------------------------------------------

def generate_round_keys(key: bytes) -> list[list[int]]:
    """Generate 16 round keys (each 48 bits) from a 64-bit (8-byte) key.

    Parameters
    ----------
    key : bytes
        Exactly 8 bytes.

    Returns
    -------
    list[list[int]]
        A list of 16 round keys, each represented as a 48-element bit list.
    """
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")

    # Convert key to 64 bits and apply PC-1 to get 56 bits
    key_bits = _bytes_to_bits(key)
    key56 = _permute(key_bits, PC1)  # 56 bits

    # Split into two 28-bit halves
    C = key56[:28]
    D = key56[28:]

    round_keys: list[list[int]] = []
    for round_num in range(16):
        # Left-rotate each half by the scheduled amount
        C = _left_rotate(C, LEFT_SHIFTS[round_num])
        D = _left_rotate(D, LEFT_SHIFTS[round_num])

        # Combine and apply PC-2 to produce a 48-bit round key
        combined = C + D  # 56 bits
        round_key = _permute(combined, PC2)  # 48 bits
        round_keys.append(round_key)

    return round_keys


# ---------------------------------------------------------------------------
#  The DES Feistel function (f)
# ---------------------------------------------------------------------------

def _feistel(right: list[int], round_key: list[int]) -> list[int]:
    """Compute the Feistel function f(R, K).

    1. Expand R from 32 bits to 48 bits using E.
    2. XOR with the 48-bit round key.
    3. Split into eight 6-bit blocks and pass through S-boxes → 32 bits.
    4. Apply the P permutation.
    """
    # Step 1: Expansion
    expanded = _permute(right, E)  # 48 bits

    # Step 2: XOR with round key
    xored = _xor(expanded, round_key)  # 48 bits

    # Step 3: S-box substitution (48 bits → 32 bits)
    sbox_output: list[int] = []
    for i in range(8):
        # Each S-box takes 6 bits
        chunk = xored[i * 6:(i + 1) * 6]
        # Row is determined by first and last bits
        row = (chunk[0] << 1) | chunk[5]
        # Column is determined by the middle 4 bits
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        # Lookup and convert to 4 bits
        val = S_BOXES[i][row][col]
        sbox_output.extend([
            (val >> 3) & 1,
            (val >> 2) & 1,
            (val >> 1) & 1,
            val & 1,
        ])

    # Step 4: Permutation P
    return _permute(sbox_output, P)


# ---------------------------------------------------------------------------
#  Single-block encrypt / decrypt
# ---------------------------------------------------------------------------

def des_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Encrypt a single 8-byte (64-bit) block using the DES algorithm.

    Parameters
    ----------
    block : bytes
        Exactly 8 bytes of plaintext.
    round_keys : list[list[int]]
        16 round keys as returned by :func:`generate_round_keys`.

    Returns
    -------
    bytes
        8 bytes of ciphertext.
    """
    if len(block) != 8:
        raise ValueError(f"Block must be exactly 8 bytes, got {len(block)}")

    bits = _bytes_to_bits(block)

    # Initial permutation
    bits = _permute(bits, IP)

    # Split into left and right halves (32 bits each)
    left = bits[:32]
    right = bits[32:]

    # 16 rounds of the Feistel network
    for i in range(16):
        new_right = _xor(left, _feistel(right, round_keys[i]))
        left = right
        right = new_right

    # After 16 rounds, combine (NOTE: swap order — right + left, not left + right)
    combined = right + left

    # Final permutation
    ciphertext_bits = _permute(combined, FP)

    return _bits_to_bytes(ciphertext_bits)


def des_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Decrypt a single 8-byte (64-bit) block using the DES algorithm.

    Decryption is identical to encryption but with round keys in reverse order.

    Parameters
    ----------
    block : bytes
        Exactly 8 bytes of ciphertext.
    round_keys : list[list[int]]
        16 round keys as returned by :func:`generate_round_keys`.

    Returns
    -------
    bytes
        8 bytes of plaintext.
    """
    # DES decryption = DES encryption with reversed round keys
    return des_encrypt_block(block, round_keys[::-1])


# ---------------------------------------------------------------------------
#  ECB-mode encrypt / decrypt with PKCS5 padding
# ---------------------------------------------------------------------------

def _pkcs5_pad(data: bytes) -> bytes:
    """Apply PKCS#5 padding to make data a multiple of 8 bytes.

    Padding always adds 1–8 bytes; even if the data is already aligned,
    a full block of padding (0x08 × 8) is appended so that unpadding is
    unambiguous.
    """
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def _pkcs5_unpad(data: bytes) -> bytes:
    """Remove PKCS#5 padding.

    Raises
    ------
    ValueError
        If the padding is invalid.
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError(f"Invalid PKCS5 padding value: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Corrupt PKCS5 padding")
    return data[:-pad_len]


def des_encrypt(plaintext_bytes: bytes, key: bytes) -> bytes:
    """Encrypt arbitrary-length data using DES in ECB mode with PKCS5 padding.

    Parameters
    ----------
    plaintext_bytes : bytes
        The data to encrypt (any length).
    key : bytes
        Exactly 8 bytes.

    Returns
    -------
    bytes
        The ciphertext (always a multiple of 8 bytes).
    """
    round_keys = generate_round_keys(key)
    padded = _pkcs5_pad(plaintext_bytes)
    ciphertext = bytearray()
    for i in range(0, len(padded), 8):
        block = padded[i:i + 8]
        ciphertext.extend(des_encrypt_block(block, round_keys))
    return bytes(ciphertext)


def des_decrypt(ciphertext_bytes: bytes, key: bytes) -> bytes:
    """Decrypt data that was encrypted with :func:`des_encrypt`.

    Parameters
    ----------
    ciphertext_bytes : bytes
        The ciphertext (must be a multiple of 8 bytes).
    key : bytes
        Exactly 8 bytes (must match the key used for encryption).

    Returns
    -------
    bytes
        The original plaintext.
    """
    if len(ciphertext_bytes) == 0 or len(ciphertext_bytes) % 8 != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 8 bytes")
    round_keys = generate_round_keys(key)
    plaintext = bytearray()
    for i in range(0, len(ciphertext_bytes), 8):
        block = ciphertext_bytes[i:i + 8]
        plaintext.extend(des_decrypt_block(block, round_keys))
    return _pkcs5_unpad(bytes(plaintext))


# ---------------------------------------------------------------------------
#  Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  DES Implementation — Self-Test")
    print("=" * 60)

    # --- Test 1: Known-answer test (NIST / FIPS 46-3 example) ---
    # Plaintext: 0x0123456789ABCDEF, Key: 0x133457799BBCDFF1
    # Expected ciphertext: 0x85E813540F0AB405
    key_nist = bytes.fromhex("133457799BBCDFF1")
    pt_nist  = bytes.fromhex("0123456789ABCDEF")
    expected_ct = bytes.fromhex("85E813540F0AB405")

    rk = generate_round_keys(key_nist)
    ct = des_encrypt_block(pt_nist, rk)
    dt = des_decrypt_block(ct, rk)

    print(f"\n[Test 1] NIST known-answer test")
    print(f"  Key        : {key_nist.hex().upper()}")
    print(f"  Plaintext  : {pt_nist.hex().upper()}")
    print(f"  Ciphertext : {ct.hex().upper()}")
    print(f"  Expected   : {expected_ct.hex().upper()}")
    print(f"  Match      : {'✓ PASS' if ct == expected_ct else '✗ FAIL'}")
    print(f"  Decrypted  : {dt.hex().upper()}")
    print(f"  Round-trip : {'✓ PASS' if dt == pt_nist else '✗ FAIL'}")

    # --- Test 2: ECB + PKCS5 padding round-trip ---
    key = b"8byteky"  # exactly 7 bytes — will need to be 8
    key = b"8bytekyx"  # exactly 8 bytes
    message = "Hello, DES encryption! This is a test of ECB mode with PKCS5 padding."
    plaintext = message.encode("utf-8")

    encrypted = des_encrypt(plaintext, key)
    decrypted = des_decrypt(encrypted, key)

    print(f"\n[Test 2] ECB + PKCS5 round-trip")
    print(f"  Key        : {key}")
    print(f"  Plaintext  : {message}")
    print(f"  Encrypted  : {encrypted.hex()}")
    print(f"  Decrypted  : {decrypted.decode('utf-8')}")
    print(f"  Match      : {'✓ PASS' if decrypted == plaintext else '✗ FAIL'}")

    # --- Test 3: Edge case — empty string ---
    empty_enc = des_encrypt(b"", key)
    empty_dec = des_decrypt(empty_enc, key)
    print(f"\n[Test 3] Empty plaintext")
    print(f"  Encrypted  : {empty_enc.hex()}")
    print(f"  Decrypted  : {empty_dec!r}")
    print(f"  Match      : {'✓ PASS' if empty_dec == b'' else '✗ FAIL'}")

    # --- Test 4: Exactly 8 bytes (full padding block added) ---
    exact8 = b"ABCDEFGH"
    enc8 = des_encrypt(exact8, key)
    dec8 = des_decrypt(enc8, key)
    print(f"\n[Test 4] Exactly 8-byte plaintext")
    print(f"  Plaintext  : {exact8}")
    print(f"  Encrypted  : {enc8.hex()}  ({len(enc8)} bytes = 2 blocks)")
    print(f"  Decrypted  : {dec8}")
    print(f"  Match      : {'✓ PASS' if dec8 == exact8 else '✗ FAIL'}")

    print("\n" + "=" * 60)
    print("  All tests complete.")
    print("=" * 60)
