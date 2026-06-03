"""
RSA Encryption/Decryption — implemented from scratch.

This module provides a complete RSA implementation using only Python's
built-in modules (`random`, `os`).  No external cryptography libraries
are used.

Key size : 512-bit (two 256-bit primes)
Public exponent : e = 65537 (standard Fermat prime)

Exported helpers
----------------
- generate_rsa_keys(bits)  → ((e, n), (d, n))
- rsa_encrypt(message_int, public_key) → ciphertext_int
- rsa_decrypt(ciphertext_int, private_key) → message_int
- bytes_to_int(data) → int
- int_to_bytes(number) → bytes
"""

import random
import os


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int) -> tuple:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Compute the modular multiplicative inverse of *e* modulo *phi*.

    Returns *d* such that  (e * d) % phi == 1.
    Raises ValueError if the inverse does not exist.
    """
    gcd, x, _ = _extended_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={gcd})")
    return x % phi


# Primality testing  (Miller-Rabin)
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
    401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
    563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
    631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
    797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
    967, 971, 977, 983, 991, 997,
]


def _is_miller_rabin_witness(a: int, d: int, n: int, r: int) -> bool:
  
    # Compute a^d mod n  
    x = pow(a, d, n)

    # If x == 1 or x == n-1, *a* is NOT a witness → n may be prime
    if x == 1 or x == n - 1:
        return False

    # Square repeatedly
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False

    # *a* IS a witness → n is definitely composite
    return True


def is_probably_prime(n: int, k: int = 40) -> bool:
    
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # try small primes
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n-1 as d * 2^r  with d odd
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # k rounds 
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if _is_miller_rabin_witness(a, d, n, r):
            return False

    return True


# ---------------------------------------------------------------------------
# Prime generation
# ---------------------------------------------------------------------------

def _generate_prime_candidate(bits: int) -> int:

    # Generate random bytes, convert to int
    n = int.from_bytes(os.urandom(bits // 8), byteorder="big")
    # Set the MSB to ensure the number is *bits* bits long
    n |= (1 << (bits - 1))
    # Set the LSB to make it odd
    n |= 1
    return n


def generate_large_prime(bits: int = 256) -> int:
    while True:
        candidate = _generate_prime_candidate(bits)
        if is_probably_prime(candidate):
            return candidate


#key gen 

def generate_rsa_keys(bits: int = 512) -> tuple:
    prime_bits = bits // 2  # 256 bits each for 512-bit RSA

    # 1. Generate two distinct large primes p and q
    p = generate_large_prime(prime_bits)
    q = generate_large_prime(prime_bits)

    # p ≠ q can be possible :) goddamn 
    while q == p:
        q = generate_large_prime(prime_bits)

    # 2. Compute n = p * q  -mod-
    n = p * q

    #euler
    phi = (p - 1) * (q - 1)

    # fermat prime (researched fast computation)
    e = 65537

    # check gcd(e, phi) == 1  rand primes
    if _gcd(e, phi) != 1:
        return generate_rsa_keys(bits)

    # d = e⁻¹ mod phi(n)
    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key



#enc/dec


def rsa_encrypt(message_int: int, public_key: tuple) -> int:
    e, n = public_key
    if message_int < 0 or message_int >= n:
        raise ValueError(
            f"Message integer ({message_int.bit_length()} bits) must be "
            f"in range [0, n) where n has {n.bit_length()} bits."
        )
    return pow(message_int, e, n)


def rsa_decrypt(ciphertext_int: int, private_key: tuple) -> int:
    d, n = private_key
    return pow(ciphertext_int, d, n)


# Byte - Integer conversion helpers


def bytes_to_int(data: bytes) -> int:
    """Convert a byte string to a non-negative integer (big-endian)."""
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(number: int) -> bytes:
    """
    Convert a non-negative integer back to a byte string (big-endian).

    The output length is the minimum number of bytes needed to represent
    the integer (at least 1 byte for zero).
    """
    if number < 0:
        raise ValueError("Cannot convert a negative integer to bytes")
    if number == 0:
        return b"\x00"
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder="big")



# Self-test

if __name__ == "__main__":
    print("=" * 60)
    print("  RSA Implementation — Self-Test")
    print("=" * 60)

    # --- Key generation ---
    print("\n[1] Generating 512-bit RSA key pair ...")
    pub, priv = generate_rsa_keys(512)
    e_val, n_val = pub
    d_val, _     = priv

    print(f"    e = {e_val}")
    print(f"    n = {n_val}")
    print(f"    n bit-length = {n_val.bit_length()}")
    print(f"    d = {d_val}")

    # --- Test 1: small integer round-trip ---
    print("\n[2] Encrypt / decrypt a small integer ...")
    original = 42
    cipher   = rsa_encrypt(original, pub)
    result   = rsa_decrypt(cipher, priv)
    assert result == original, f"FAIL: got {result}, expected {original}"
    print(f"    original  = {original}")
    print(f"    encrypted = {cipher}")
    print(f"    decrypted = {result}  ✓")

    # --- Test 2: byte-string round-trip (simulating a DES key) ---
    print("\n[3] Encrypt / decrypt an 8-byte DES key ...")
    des_key       = os.urandom(8)                    # random 8-byte key
    des_key_int   = bytes_to_int(des_key)
    cipher_int    = rsa_encrypt(des_key_int, pub)
    plain_int     = rsa_decrypt(cipher_int, priv)
    recovered_key = int_to_bytes(plain_int)

    # int_to_bytes returns minimal bytes; pad back to original length
    if len(recovered_key) < len(des_key):
        recovered_key = b"\x00" * (len(des_key) - len(recovered_key)) + recovered_key

    assert recovered_key == des_key, (
        f"FAIL: recovered {recovered_key.hex()}, expected {des_key.hex()}"
    )
    print(f"    DES key   = {des_key.hex()}")
    print(f"    encrypted = {cipher_int}")
    print(f"    decrypted = {recovered_key.hex()}  ✓")

    # --- Test 3: larger message ---
    print("\n[4] Encrypt / decrypt a text message ...")
    message       = b"Hello, RSA!"
    msg_int       = bytes_to_int(message)
    cipher_int    = rsa_encrypt(msg_int, pub)
    plain_int     = rsa_decrypt(cipher_int, priv)
    recovered_msg = int_to_bytes(plain_int)
    assert recovered_msg == message, (
        f"FAIL: recovered {recovered_msg!r}, expected {message!r}"
    )
    print(f"    message   = {message!r}")
    print(f"    encrypted = {cipher_int}")
    print(f"    decrypted = {recovered_msg!r}  ✓")

    print("\n" + "=" * 60)
    print("  All tests passed!")
    print("=" * 60)
