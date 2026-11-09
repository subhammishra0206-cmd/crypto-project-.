from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def generate_keys(bits: int = 2048):
    private_key = RSA.generate(bits)
    return private_key, private_key.publickey()


def rsa_encrypt(message: bytes, public_key) -> bytes:
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


def sign(message: bytes, private_key) -> bytes:
    return pss.new(private_key).sign(SHA256.new(message))


def verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        pss.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


def run():
    print("\n=== RSA-2048 ===")
    print("Generating key pair...")
    private_key, public_key = generate_keys()

    with open("private.pem", "wb") as f:
        f.write(private_key.export_key())
    with open("public.pem", "wb") as f:
        f.write(public_key.export_key())
    print("Keys saved: private.pem, public.pem")

    message = input("Enter short message (max ~190 chars): ").encode("utf-8")

    ciphertext = rsa_encrypt(message, public_key)
    print("Encrypted (hex):", ciphertext.hex()[:80], "...")
    print("Decrypted      :", rsa_decrypt(ciphertext, private_key).decode())

    signature = sign(message, private_key)
    print("Signature valid?        ", verify(message, signature, public_key))
    print("Tampered message valid? ", verify(message + b"!", signature, public_key))


if __name__ == "__main__":
    run()
    