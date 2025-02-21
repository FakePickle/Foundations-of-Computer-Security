import gmpy2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import number
from Cryptodome.Cipher import Salsa20

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

def salsa20_encrypt(message: bytes, key: bytes) -> tuple:
    """Encrypt a message using Salsa20 and return ciphertext with nonce."""
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(message)
    return ciphertext, cipher.nonce  # Return both ciphertext and nonce

def salsa20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt a message using Salsa20 with the correct nonce."""
    cipher = Salsa20.new(key=key, nonce=nonce)  # Use the same nonce
    return cipher.decrypt(ciphertext)

# Main Function
if __name__ == "__main__":
    # A. Alice generates the shared symmetric key: Generate random 16 byte string.
    # This would be used as the key for Salsa20 encryption. Return this byte string. [3]
    symmetric_key = generate_symmetric_key()
    print("Alice generated a symmetric key.")
    print(f"Alice's symmetric key: {symmetric_key.hex()}")

    # B. Bob generates his asymmetric keys: Use the GMP library to implement RSA.
    # Take prime numbers ʻpʼ and ʻqʼ as inputs and generate ʻnʼ, ʻeʼ and ʻdʼ for Bob.
    # (n, e) is the public key, (n, d) is the private key. Return Bobʼs public key and private key. [7]
    p = number.getPrime(128)
    q = number.getPrime(128)
    public_key, private_key = generate_rsa_keys(p, q)
    print("\nBob generated RSA keys.")
    print(f"Bob's Public Key: {public_key}")
    print(f"Bob's Private Key: {private_key}")

    # C. Alice uses Bobʼs public key to encrypt K: Use the symmetric key generated in part 1.a. as the message and encrypt it using Bobʼs public key. Return the ciphertext ʻcʼ. [5]
    encrypted_symmetric_key = rsa_encrypt(symmetric_key, public_key)
    print("\nAlice encrypted the symmetric key.")
    print(f"Encrypted symmetric key: {encrypted_symmetric_key}")

    # D. Bob obtains the shared symmetric key: Given the ciphertext ʻcʼ, use Bobʼs private key to decrypt the message. Bob has now received the shared symmetric key K. Return K.[5]
    decrypted_symmetric_key = rsa_decrypt(encrypted_symmetric_key, private_key)
    print("\nBob decrypted the symmetric key.")
    print(f"Bob's decrypted symmetric key: {decrypted_symmetric_key.hex()}")

    # Verify correctness
    assert symmetric_key == decrypted_symmetric_key, "Decryption failed!"

    print("\nNow Bob has the symmetric key and can use it for encryption/decryption.")
    
    # Bob will now use the symmetric key to send a message to Alice
    message = b"Hello Alice! This is Bob."
    print(f"\nBob's message: {message}")

    # E. Bob encrypts a message using shared symmetric key: Use the key K to encrypt a
    # given message ʻmʼ (byte string) on Bobʼs end and return the encrypted message.[5]
    salsa20_ciphertext, nonce = salsa20_encrypt(message, symmetric_key)
    print(f"\nBob encrypted the message using Salsa20: {salsa20_ciphertext.hex()}")
    print(f"Salsa20 nonce: {nonce.hex()}")

    # Alice will decrypt the message using the symmetric key
    # F. Alice decrypts Bobʼs message: Given the ciphertext, use the shared key K to decrypt Bobʼs message at Aliceʼs end and return the decrypted message. [5]
    decrypted_message = salsa20_decrypt(salsa20_ciphertext, symmetric_key, nonce)
    print(f"\nAlice decrypted the message: {decrypted_message.decode()}")