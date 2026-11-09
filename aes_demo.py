from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def derive_key(password: str, salt: bytes) -> bytes:
    """Turn a password into a 256-bit AES key."""
    return PBKDF2(password, salt, dkLen=32, count=200_000, hmac_hash_module=SHA256)


def aes_encrypt(plaintext: str, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    # Package: salt(16) + nonce(16) + tag(16) + ciphertext
    return salt + cipher.nonce + tag + ciphertext


def aes_decrypt(blob: bytes, password: str) -> str:
    salt, nonce, tag, ciphertext = blob[:16], blob[16:32], blob[32:48], blob[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def run():
    print("\n=== AES-256-GCM ===")
    message = input("Enter message to encrypt: ")
    password = input("Enter password: ")

    encrypted = aes_encrypt(message, password)
    print("Encrypted (hex):", encrypted.hex())

    try:
        decrypted = aes_decrypt(encrypted, password)
        print("Decrypted      :", decrypted)
    except ValueError:
        print("Decryption failed: wrong password or data was tampered with.")


if __name__ == "__main__":
    run()
    