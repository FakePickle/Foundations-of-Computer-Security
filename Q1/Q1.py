import gmpy2
from Crypto.Random import get_random_bytes
from Crypto.Util import number

def generate_symmetric_key():
    """Generate a random 16-byte key for Salsa20 encryption."""
    return get_random_bytes(16)

def generate_rsa_keys(p: int, q: int):
    """Generate RSA public and private keys given two prime numbers."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = gmpy2.invert(e, phi)  # Compute modular inverse
    return (n, e), (n, int(d))

def rsa_encrypt(message: bytes, public_key: tuple) -> int:
    """Encrypt a message using RSA public key."""
    n, e = public_key
    message_int = int.from_bytes(message, byteorder='big')
    ciphertext = pow(message_int, e, n)
    return ciphertext

def rsa_decrypt(ciphertext: int, private_key: tuple) -> bytes:
    """Decrypt a message using RSA private key."""
    n, d = private_key
    decrypted_int = pow(ciphertext, d, n)
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    return decrypted_bytes

# Main Function
if __name__ == "__main__":
    # Step A: Alice generates a symmetric key
    symmetric_key = generate_symmetric_key()
    print(f"Alice's symmetric key: {symmetric_key.hex()}")

    # Step B: Bob generates RSA keys
    p = number.getPrime(128)
    q = number.getPrime(128)
    public_key, private_key = generate_rsa_keys(p, q)
    print(f"Bob's Public Key: {public_key}")
    print(f"Bob's Private Key: {private_key}")

    # Step C: Alice encrypts the symmetric key using Bob's public key
    encrypted_symmetric_key = rsa_encrypt(symmetric_key, public_key)
    print(f"Encrypted symmetric key: {encrypted_symmetric_key}")

    # Step D: Bob decrypts the symmetric key using his private key
    decrypted_symmetric_key = rsa_decrypt(encrypted_symmetric_key, private_key)
    print(f"Bob's decrypted symmetric key: {decrypted_symmetric_key.hex()}")

    # Verify correctness
    assert symmetric_key == decrypted_symmetric_key, "Decryption failed!"
