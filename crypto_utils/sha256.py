"""
SHA-256 Implementation from Scratch
====================================
Follows FIPS 180-4 (Secure Hash Standard).
No external cryptographic libraries used — only Python's built-in `struct` module.

References:
  - FIPS 180-4: https://csrc.nist.gov/publications/detail/fips/180/4/final
  - Section 4.2.2 — SHA-256 Constants
  - Section 5.1.1 — Padding the Message
  - Section 5.2.1 — Parsing the Padded Message
  - Section 6.2   — SHA-256 Hash Computation
"""

import struct


# ---------------------------------------------------------------------------
# Section 4.2.2 — SHA-256 Constants
# ---------------------------------------------------------------------------

# Initial hash values H0..H7
# These are the first 32 bits of the fractional parts of the square roots
# of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19).
H_INITIAL = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

# 64 round constants K[0..63]
# These are the first 32 bits of the fractional parts of the cube roots
# of the first 64 prime numbers (2 .. 311).
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

# All arithmetic is modulo 2^32 (32-bit words).
MASK_32 = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Section 4.1.2 — SHA-256 Functions
# ---------------------------------------------------------------------------

def _rotr(x: int, n: int) -> int:
    """Right-rotate a 32-bit integer x by n bits."""
    return ((x >> n) | (x << (32 - n))) & MASK_32


def _shr(x: int, n: int) -> int:
    """Right-shift a 32-bit integer x by n bits."""
    return x >> n


def _ch(x: int, y: int, z: int) -> int:
    """Choice function: Ch(x, y, z) = (x AND y) XOR (NOT x AND z)."""
    return (x & y) ^ (~x & z) & MASK_32


def _maj(x: int, y: int, z: int) -> int:
    """Majority function: Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)."""
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
    """Σ0(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x: int) -> int:
    """Σ1(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _small_sigma0(x: int) -> int:
    """σ0(x) = ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _small_sigma1(x: int) -> int:
    """σ1(x) = ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


# ---------------------------------------------------------------------------
# Section 5.1.1 — Padding the Message
# ---------------------------------------------------------------------------

def _pad(message: bytes) -> bytes:
    """
    Pad the message according to SHA-256 rules (FIPS 180-4 §5.1.1):
      1. Append a single '1' bit (0x80 byte).
      2. Append '0' bits until message length ≡ 448 (mod 512), i.e. 56 (mod 64) bytes.
      3. Append the original message length as a 64-bit big-endian integer.
    """
    msg_len_bits = len(message) * 8  # original length in bits

    # Step 1: append the 0x80 byte (a '1' bit followed by seven '0' bits)
    message += b'\x80'

    # Step 2: pad with zero bytes until length ≡ 56 mod 64
    # We need (current_length % 64) == 56.
    while len(message) % 64 != 56:
        message += b'\x00'

    # Step 3: append the original length as a 64-bit big-endian integer
    message += struct.pack('>Q', msg_len_bits)

    return message


# ---------------------------------------------------------------------------
# Section 5.2.1 — Parsing into 512-bit (64-byte) Blocks
# ---------------------------------------------------------------------------

def _parse_blocks(padded: bytes):
    """Yield successive 512-bit (64-byte) blocks from the padded message."""
    for i in range(0, len(padded), 64):
        yield padded[i:i + 64]


# ---------------------------------------------------------------------------
# Section 6.2 — SHA-256 Hash Computation
# ---------------------------------------------------------------------------

def _process_block(block: bytes, h: list) -> list:
    """
    Process a single 512-bit block and update the hash state.

    Parameters
    ----------
    block : bytes
        A 64-byte block from the padded message.
    h : list of int
        Current hash values [H0, H1, ..., H7] (each a 32-bit word).

    Returns
    -------
    list of int
        Updated hash values after processing this block.
    """
    # ---- Step 1: Prepare the message schedule W[0..63] --------------------
    # W[0..15] are taken directly from the block (16 × 32-bit big-endian words).
    W = list(struct.unpack('>16L', block))

    # W[16..63] are derived from previous W values.
    for t in range(16, 64):
        w = (_small_sigma1(W[t - 2]) + W[t - 7] +
             _small_sigma0(W[t - 15]) + W[t - 16]) & MASK_32
        W.append(w)

    # ---- Step 2: Initialise working variables ----------------------------
    a, b, c, d, e, f, g, hh = h

    # ---- Step 3: 64 rounds of compression --------------------------------
    for t in range(64):
        T1 = (hh + _big_sigma1(e) + _ch(e, f, g) + K[t] + W[t]) & MASK_32
        T2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK_32

        hh = g
        g = f
        f = e
        e = (d + T1) & MASK_32
        d = c
        c = b
        b = a
        a = (T1 + T2) & MASK_32

    # ---- Step 4: Compute the new intermediate hash values ----------------
    return [
        (h[0] + a) & MASK_32,
        (h[1] + b) & MASK_32,
        (h[2] + c) & MASK_32,
        (h[3] + d) & MASK_32,
        (h[4] + e) & MASK_32,
        (h[5] + f) & MASK_32,
        (h[6] + g) & MASK_32,
        (h[7] + hh) & MASK_32,
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> bytes:
    """
    Compute the SHA-256 digest of *data*.

    Parameters
    ----------
    data : bytes
        Arbitrary-length input message.

    Returns
    -------
    bytes
        The 32-byte (256-bit) SHA-256 digest.
    """
    # Start with the initial hash values.
    h = list(H_INITIAL)

    # Pad the message and split into 512-bit blocks.
    padded = _pad(bytearray(data))

    # Process each block.
    for block in _parse_blocks(padded):
        h = _process_block(block, h)

    # Produce the final 256-bit digest by concatenating H0..H7.
    return struct.pack('>8L', *h)


def sha256(data: bytes) -> str:
    """
    Compute the SHA-256 hex-digest of *data*.

    Parameters
    ----------
    data : bytes
        Arbitrary-length input message.

    Returns
    -------
    str
        The 64-character lowercase hexadecimal digest string.
    """
    return sha256_bytes(data).hex()


# ---------------------------------------------------------------------------
# Self-test — FIPS 180-4 test vectors
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Test vector 1: one-block message "abc"
    test1_input = b'abc'
    test1_expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

    # Test vector 2: empty message ""
    test2_input = b''
    test2_expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    # Test vector 3: two-block message (exactly 448 bits = 56 bytes)
    test3_input = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    test3_expected = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'

    passed = 0
    total = 3

    for i, (inp, expected) in enumerate([
        (test1_input, test1_expected),
        (test2_input, test2_expected),
        (test3_input, test3_expected),
    ], start=1):
        result = sha256(inp)
        ok = result == expected
        status = 'PASS' if ok else 'FAIL'
        if ok:
            passed += 1
        print(f'Test {i} [{status}]: sha256({inp!r})')
        if not ok:
            print(f'  Expected: {expected}')
            print(f'  Got:      {result}')

    print(f'\n{passed}/{total} tests passed.')
