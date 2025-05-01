from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import binascii
import secrets

# iv = bytes.fromhex(secrets.token_hex(16))
iv = bytes.fromhex("AED98227C2321A5CEE4F27838D67C91B") # Based on server?
message = b"\x01" * 16


def encrypt_aes_128_cbc(key):
    key = bytes.fromhex(key)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    ciphertext = iv + ciphertext
    return ciphertext

def decrypt_aes_128_cbc(key, ciphertext):
    key = bytes.fromhex(key)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(ciphertext[:16]), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded)
    plaintext += unpadder.finalize()
    return plaintext
