import aes_cbc
from flask import jsonify
from frodokem import FrodoKEM
import os
# app.secret_key = os.urandom(24)


class LocalServer():
    def __init__(self, variant, determ=False):
        self.variant = variant
        self.determ = determ
        self.kem = FrodoKEM(variant)

    def check_server(self):
        print('Server is up and running!')
        return 'Server is up and running!'

    def call_first_interface(self, uid):
        directory = 'student_files'
        if not os.path.exists(directory):
            os.makedirs(directory)
        filename = os.path.join(directory, f"{uid}.txt")

        if not filename and self.determ:
            raise FileNotFoundError("Can't find file - run once non-deterministically to generate a key")

        (pk,sk) = self.kem.kem_keygen()
        if self.determ:
            with open(filename, 'r') as file:
                content = file.read()
                pk = bytes.fromhex(content.split('Public Key: ')[1].split('\n')[0])
                sk = bytes.fromhex(content.split('Secret Key: ')[1].split('\n')[0])
        pk_hex = pk.hex().upper()
        sk_hex = sk.hex().upper()
        seedA = pk_hex[0:32]
        b = pk_hex[32:]
        true_secret = sk_hex[19264:]
        with open(filename, 'w') as file:
            file.write(f"Variant: {self.variant}\n")
            file.write(f"Public Key: {pk_hex}\n")
            file.write(f"seedA: {seedA}\n")
            file.write(f"b: {b}\n")
            file.write(f"Secret Key: {sk_hex}\n")
            file.write(f"True Secret: {true_secret}\n")
        print("Key pair generated and stored")
        # print(f"Public Key: {pk_hex}")
        # print(f"seedA: {seedA}")
        # print(f"b: {b}")
        return pk_hex, seedA, b

    def call_second_interface(self, uid, cipher_text):
        filename = os.path.join('student_files', f"{uid}.txt")
        if not filename:
            return jsonify({'error': 'Invalid UID'}), 400
        with open(filename, 'r') as file:
            content = file.read()
            variant = content.split('Variant: ')[1].split('\n')[0]
            secret_key = content.split('Secret Key: ')[1].split('\n')[0]
        kem_instance = FrodoKEM(variant)
        ss_d = kem_instance.kem_decaps(bytes.fromhex(secret_key), bytes.fromhex(cipher_text))
        if len(ss_d) == 4: # Small-FrodoKEM hack
            ss_d = ss_d + b"\x01" * 12
        modified_cipher_text = aes_cbc.encrypt_aes_128_cbc(ss_d.hex().upper())
        with open(filename, 'a') as file:
            file.write(f"Shared Secret Decapsulated: {ss_d.hex().upper()}\n")
            file.write(f"Modified Cipher Text: {modified_cipher_text.hex().upper()}\n")
        # print("AES Ciphertext Returned")
        return modified_cipher_text.hex().upper()

    def call_third_interface(self, uid, secret_key):
        filename = os.path.join('student_files', f"{uid}.txt")
        if not filename:
            raise FileNotFoundError("Can't find file")
        with open(filename, 'r') as file:
            content = file.read()
            true_secret_key = content.split('True Secret: ')[1].split('\n')[0]
        if true_secret_key == secret_key:
            print("And hast thou slain the Jabberwock?\nCome to my arms, my beamish cryptographer!\nO frabjous day! Callooh! Callay!\nHe chortled in his joy.")
        else:
            print("Secret Key guess was incorrect.\nThe Server refused to yield!")

