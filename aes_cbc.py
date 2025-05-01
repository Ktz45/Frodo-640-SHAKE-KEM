from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import binascii
import secrets

iv = bytes.fromhex(secrets.token_hex(16))
message = b"\x01" * 16


def encrypt_aes_128_cbc(key_hex, plaintext, verbose=False):
    from Crypto.Cipher import AES
    key = bytes.fromhex(key_hex)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    if verbose:
        print(f"[AES-ENC] Key: {key.hex().upper()}")
        print(f"[AES-ENC] IV: {iv.hex().upper()}")
        print(f"[AES-ENC] Plaintext: {plaintext}")
        print(f"[AES-ENC] Padded: {padded}")
        print(f"[AES-ENC] Ciphertext: {ciphertext.hex().upper()}")
    return iv + ciphertext

def decrypt_aes_128_cbc(key_hex, ciphertext, verbose=False):
    from Crypto.Cipher import AES
    key = bytes.fromhex(key_hex)
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    if verbose:
        print(f"[AES-DEC] Key: {key.hex().upper()}")
        print(f"[AES-DEC] IV: {iv.hex().upper()}")
        print(f"[AES-DEC] Ciphertext: {ct.hex().upper()}")
        print(f"[AES-DEC] Padded: {padded}")
        print(f"[AES-DEC] Plaintext: {plaintext}")
    return plaintext
