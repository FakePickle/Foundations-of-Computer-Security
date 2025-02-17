from Cryptodome.Cipher import Salsa20
import gmpy2
import os

# Generating a random 16-byte String key for Salsa20 encryption
def generate_key() -> bytes:
    return os.urandom(16)

# Encrypting plaintext using Salsa20 encryption
def encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = Salsa20.new(key)
    return cipher.encrypt(plaintext)

# Decrypting ciphertext using Salsa20 encryption
def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Salsa20.new(key)
    return cipher.decrypt(ciphertext)

def rsa_encrypt(public_key: tuple, plaintext: bytes) -> bytes:
    n, e = public_key
    plaintext_int = int.from_bytes(plaintext, "big")
    
    # Ensure plaintext is smaller than n
    if plaintext_int >= n:
        raise ValueError("Plaintext too large for RSA encryption")

    encrypted_int = pow(plaintext_int, e, n)
    return encrypted_int.to_bytes((n.bit_length() + 7) // 8, "big")


def rsa_decrypt(private_key: tuple, ciphertext: bytes) -> bytes:
    n, d = private_key
    ciphertext_int = int.from_bytes(ciphertext, "big")
    decrypted_int = pow(ciphertext_int, d, n)
    
    return decrypted_int.to_bytes((n.bit_length() + 7) // 8, "big")


# Main function
if __name__ == "__main__":
    """
    A. Alice generates the shared symmetric key: Generate random 16 byte string. This
    would be used as the key for Salsa20 encryption. Return this byte string. [3]
    """
    # Generate a random key for Alice
    key = generate_key()

    # Printing Alice's key
    print("Alice's key: ", key)

    """
    B. Bob generates his asymmetric keys: Use the GMP library to implement RSA. Take
    prime numbers 'p' and 'q' as inputs and generate 'n', 'e' and 'd' for Bob. (n, e) is the
    public key, (n, d) is the private key. Return Bob's public key and private key. [7]
    """
    # Taking input for p and q for RSA encryption for Bob and generate n, e and d
    p = int(input("Enter p: "))
    q = int(input("Enter q: "))
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = gmpy2.invert(e, phi)

    # Printing Bob's public and private keys
    print("Bob's public key: (" + str(n) + "," + str(e) + ")")
    print("Bob's private key: (" + str(n) + "," + str(d) + ")")

    """
    C. Alice uses Bob's public key to encrypt K: Use the symmetric key generated in part 1.a.
    as the message and encrypt it using Bob's public key. Return the ciphertext 'c'. [5]
    """
    encrypted_message = rsa_encrypt((n, e), key)
    print("Cipher Text: ", encrypted_message)
    print("Decrypting the cipher text: ", rsa_decrypt((n, d), encrypted_message))