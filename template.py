from frodokem import FrodoKEM
import aes_cbc

import requests

# Change to BASE_URL: http://sp25cmsc656.cs.umd.edu:5001/
BASE_URL: str = 'http://127.0.0.1:5000/' 
TEST_URL = f'{BASE_URL}/check'
first_interface = f"{BASE_URL}/1st-interface"
second_interface = f"{BASE_URL}/2nd-interface"
third_interface = f"{BASE_URL}/3rd-interface"


def check_server():
    response = requests.get(TEST_URL)
    if response.status_code == 200:
        print(response.text)
    else:
        print("Server is not running.")


def call_first_interface(string_value):
    data = {'UID': string_value}
    try:
        response = requests.post(first_interface, json=data)
        if response.status_code == 200:
            result = response.json()
            public_key = result.get('public_key')
            seedA = result.get('seedA')
            b = result.get('b')
            if public_key and seedA and b:
                print("Key pair generated and stored.")
                print(f"Public Key: {public_key}")
                print(f"seedA: {seedA}")
                print(f"b: {b}")
                return public_key, seedA, b
            else:
                print("Missing key data in response.")
                return None
        else:
            print("Failed to generate key pair.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")
        return None


def call_second_interface(uid, cipher_text):
    data = {'UID': uid, 'cipher_text': cipher_text}
    try:
        response = requests.post(second_interface, json=data)
        if response.status_code == 200:
            result = response.json()
            ss_d = result.get('new_cipher')
            aes_key = result.get('aes_key')
            print("AES Encrypted Ciphertext returned.")
            # print(f"NEW CIPHER: {ss_d}")
            return ss_d, aes_key
        else:
            print(f"Failed to encrypt data. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")


def call_third_interface(uid, secret_key):
    data = {'UID': uid, 'secret_key': secret_key}
    try:
        response = requests.post(third_interface, json=data)
        if response.status_code == 200:
            result = response.json()
            ss_d = result.get('message')
            print(f"MESSAGE: {ss_d}")
        else:
            print(f"Failed to encrypt data. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")


if __name__ == "__main__":
    UID = 'test3'
    check_server()

    # 1st Interface
    pk, seedA, b = call_first_interface(UID)
    
    # IMPLEMENT REST OF THE CODE # 
