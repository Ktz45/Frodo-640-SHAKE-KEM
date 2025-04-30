from frodokem import FrodoKEM
from remote_server import RemoteServer
from local_server import LocalServer
from enum import Enum
import aes_cbc
import secrets

import requests

class ServerMode(Enum):
    REMOTE = 1
    LOCAL = 2

MODE = ServerMode.LOCAL
VARIANT = "FrodoKEM-640-SHAKE"
BASE_URL: str = "http://sp25cmsc656.cs.umd.edu:5001/"
TEST_URL = f'{BASE_URL}/check'
first_interface = f"{BASE_URL}/1st-interface"
second_interface = f"{BASE_URL}/2nd-interface"
third_interface = f"{BASE_URL}/3rd-interface"

if __name__ == "__main__":
    server = None
    if MODE == ServerMode.REMOTE:
        server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)
    elif MODE == ServerMode.LOCAL:
        server = LocalServer()

    UID = '119008041'
    server.check_server()

    kem_instance = FrodoKEM(VARIANT)
    # 1st Interface
    pk, seedA, b = server.call_first_interface(UID)
    ct, ss =  kem_instance.kem_encaps(bytes.fromhex(pk)) # Create honest ciphertext?
    aes_ct = server.call_second_interface(UID, ct.hex().upper())

    server.call_third_interface(UID, "TEST")
    
    # IMPLEMENT REST OF THE CODE # 
