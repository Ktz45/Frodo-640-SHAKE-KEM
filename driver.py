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
Q = 32768

def __matrix_mul(X, Y):
    """Compute matrix multiplication X * Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == nrows_Y, "Mismatched matrix dimensions"
    R = [[0 for j in range(ncols_Y)] for i in range(nrows_X)]
    for i in range(nrows_X):
        for j in range(ncols_Y):
            for k in range(ncols_X):
                R[i][j] += X[i][k] * Y[k][j]
            R[i][j] %= Q
    return R

def __matrix_add(X, Y):
    """Compute matrix addition X + Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
    return [[(X[i][j] + Y[i][j]) % Q for j in range(ncols_X)] for i in range(nrows_X)]

def __matrix_sub(X, Y):
    """Compute matrix subtraction X - Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
    return [[(X[i][j] - Y[i][j]) % Q for j in range(ncols_X)] for i in range(nrows_X)]

def __matrix_transpose(X):
    """Compute transpose of matrix X"""
    nrows = len(X)
    ncols = len(X[0])
    return [[X[j][i] for j in range(nrows)] for i in range(ncols)]


def encaps(kem, r, seedA, b, e1, e2, k, delta=0):
    """
    Emulate kem_encaps with custom set terms
    """
    ct = None
    ss = None
    # A = kem.encode(seedA)
    A = kem.gen(bytes.fromhex(seedA))
    print(len(A), len(A[0]))
    B = kem.unpack(bytes.fromhex(b), 640, 8)
    R = [[1 for j in range(640)] for i in range(8)]
    E1 = [[0 for j in range(640)] for i in range(8)]
    E2 = [[0 for j in range(8)] for i in range(8)]
    K = [[Q//4 for j in range(8)] for i in range(8)]
    D = [[delta for j in range(8)] for i in range(8)]
    print(D)
    Bprime = __matrix_add(__matrix_mul(R, A), E1)
    c1 = kem.pack(Bprime)
    V = __matrix_add(__matrix_add(__matrix_mul(R, B), E2), D)
    C = __matrix_add(V, K)
    c2 = kem.pack(C)
    
    salt = ""
    for _ in range(kem.len_salt_bytes + 32):
        salt += "A"
    bytes_salt = bytes.fromhex(salt)
    ss = kem.pack(K)
    print(len(c1))
    print(len(c2))
    ct = c1 + c2 + bytes_salt
    print(len(ct))
    return ct, ss

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
    ct, ss = encaps(kem_instance, None, seedA, b, None, None, None, delta=(Q))
    aes_ct = server.call_second_interface(UID, ct.hex().upper())
    # print(aes_cbc.decrypt_aes_128_cbc(ss.hex().upper(), aes_ct))

    server.call_third_interface(UID, "TEST")
    
    # IMPLEMENT REST OF THE CODE # 
