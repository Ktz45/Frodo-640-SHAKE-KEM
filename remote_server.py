import requests


class RemoteServer():
    def __init__(self, test_url, if1, if2, if3):
        self.test_url = test_url
        self.if1 = if1
        self.if2 = if2
        self.if3 = if3

    def check_server(self):
        response = requests.get(self.test_url)
        if response.status_code == 200:
            print(response.text)
        else:
            print("Server is not running.")


    def call_first_interface(self, string_value):
        data = {'UID': string_value}
        try:
            response = requests.post(self.if1, json=data)
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


    def call_second_interface(self, uid, cipher_text):
        data = {'UID': uid, 'cipher_text': cipher_text}
        try:
            response = requests.post(self.if2, json=data)
            if response.status_code == 200:
                result = response.json()
                ss_d = result.get('new_cipher')
                # aes_key = result.get('aes_key')
                # print("AES Encrypted Ciphertext returned.")
                # print(f"NEW CIPHER: {ss_d}")
                # return ss_d, aes_key
                return ss_d
            else:
                print(f"Failed to encrypt data. Status code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")


    def call_third_interface(self, uid, secret_key):
        data = {'UID': uid, 'secret_key': secret_key}
        try:
            response = requests.post(self.if3, json=data)
            if response.status_code == 200:
                result = response.json()
                ss_d = result.get('message')
                print(f"MESSAGE: {ss_d}")
            else:
                print(f"Failed to encrypt data. Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request Exception: {e}")

