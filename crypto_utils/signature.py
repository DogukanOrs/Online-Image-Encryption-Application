"""
Digital Signature module for IEA.
Uses custom SHA-256 for hashing and custom RSA for signing/verifying.
No external crypto libraries.

Sign: SHA-256 hash of data -> RSA encrypt hash with private key
Verify: RSA decrypt signature with public key -> compare with SHA-256 hash of data
"""

from crypto_utils.sha256 import sha256, sha256_bytes
from crypto_utils.rsa import rsa_encrypt, rsa_decrypt, bytes_to_int, int_to_bytes


def sign(data, private_key):
    """
    Create a digital signature for data.

    Args:
        data: bytes to sign
        private_key: (d, n) RSA private key tuple

    Returns:
        signature as integer
    """
    # Hash the data with SHA-256
    hash_bytes = sha256_bytes(data)
    hash_int = bytes_to_int(hash_bytes)

    # Sign (encrypt hash with private key)
    # Note: In RSA signatures, we "encrypt" with the private key
    # This is just modular exponentiation: hash^d mod n
    d, n = private_key
    signature = pow(hash_int, d, n)
    return signature


def verify(data, signature, public_key):
    """
    Verify a digital signature.

    Args:
        data: original bytes that were signed
        signature: signature integer to verify
        public_key: (e, n) RSA public key tuple

    Returns:
        True if signature is valid, False otherwise
    """
    # Hash the data with SHA-256
    hash_bytes = sha256_bytes(data)
    hash_int = bytes_to_int(hash_bytes)

    # "Decrypt" the signature with public key: sig^e mod n
    e, n = public_key
    recovered_hash = pow(signature, e, n)

    # Compare
    return recovered_hash == hash_int


if __name__ == "__main__":
    from crypto_utils.rsa import generate_rsa_keys

    print("=" * 60)
    print("  Digital Signature — Self-Test")
    print("=" * 60)

    # Generate keys
    print("\n[1] Generating RSA keys...")
    public_key, private_key = generate_rsa_keys(512)
    print(f"    Keys generated (512-bit)")

    # Test 1: Sign and verify a message
    print("\n[2] Sign and verify a text message...")
    message = b"Hello, this is a test message for digital signature!"
    sig = sign(message, private_key)
    print(f"    Message  : {message}")
    print(f"    Signature: {sig}")
    valid = verify(message, sig, public_key)
    print(f"    Valid    : {valid}  {'✓' if valid else '✗'}")
    assert valid, "Signature verification failed!"

    # Test 2: Tampered message should fail
    print("\n[3] Verify with tampered message (should fail)...")
    tampered = b"Hello, this is a TAMPERED message for digital signature!"
    valid_tampered = verify(tampered, sig, public_key)
    print(f"    Tampered : {tampered}")
    print(f"    Valid    : {valid_tampered}  {'✗ PASS (correctly rejected)' if not valid_tampered else '✓ FAIL'}")
    assert not valid_tampered, "Tampered message should not verify!"

    # Test 3: Sign image-like data (random bytes)
    import os
    print("\n[4] Sign and verify binary data (simulating image)...")
    fake_image = os.urandom(1024)
    sig2 = sign(fake_image, private_key)
    valid2 = verify(fake_image, sig2, public_key)
    print(f"    Data size: {len(fake_image)} bytes")
    print(f"    Valid    : {valid2}  {'✓' if valid2 else '✗'}")
    assert valid2, "Binary data signature failed!"

    # Test 4: Wrong key should fail
    print("\n[5] Verify with wrong public key (should fail)...")
    wrong_pub, wrong_priv = generate_rsa_keys(512)
    valid_wrong = verify(message, sig, wrong_pub)
    print(f"    Valid    : {valid_wrong}  {'✗ PASS (correctly rejected)' if not valid_wrong else '✓ FAIL'}")
    assert not valid_wrong, "Wrong key should not verify!"

    print("\n" + "=" * 60)
    print("  All signature tests passed!")
    print("=" * 60)
