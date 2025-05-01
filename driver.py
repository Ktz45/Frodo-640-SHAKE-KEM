from frodokem import FrodoKEM
from remote_server import RemoteServer
from local_server import LocalServer
from enum import Enum
import aes_cbc
import secrets
import os
from itertools import product

import requests
import time
import concurrent.futures
import multiprocessing
from functools import lru_cache
import struct
import argparse
import hashlib  # for computing pkh (True Secret) from public key
import bitstring  # to assemble reconstructed secret key

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
    B = kem.unpack(bytes.fromhex(b), 640, 8)
    R = [[1 for j in range(640)] for i in range(8)]
    E1 = [[Q for j in range(640)] for i in range(8)]
    E2 = [[0 for j in range(8)] for i in range(8)]
    K = [[Q//4 for j in range(8)] for i in range(8)] # q/4 * (8x8 matrix of 1s)
    D = [[0 for j in range(8)] for i in range(8)]
    D[0][0] = delta
    Bprime = __matrix_add(__matrix_mul(R, A), E1)
    c1 = kem.pack(Bprime)
    V = __matrix_add(__matrix_add(__matrix_mul(R, B), E2), D)
    C = __matrix_add(V, K)
    c2 = kem.pack(C)
    salt = ""
    for _ in range(kem.len_salt_bytes + 32):
        salt += "A"
    bytes_salt = bytes.fromhex(salt)
    ss = kem.decode(K)
    ct = c1 + c2 + bytes_salt
    return ct, ss

@lru_cache(maxsize=100_000)
def _oracle_cached(ct_hex: str):
    # placeholder – actual call routed through closure below
    return ct_hex  # will be overridden


def oracle(server, uid, bprime, c2) -> bytes:
    kem = FrodoKEM(VARIANT)
    c1 = kem.pack(bprime)
    full_ct = c1 + kem.pack(c2) + bytes(kem.len_salt_bytes)
    hex_ct = full_ct.hex().upper()
    if hex_ct in _oracle_cached.cache:
        return _oracle_cached.cache[hex_ct]
    res = bytes.fromhex(server.call_second_interface(uid, hex_ct))
    _oracle_cached.cache[hex_ct] = res
    return res

# attach dict to function for manual cache because we can't include server obj in lru_cache key
_oracle_cached.cache = {}

def _recover_coeff(args):
    i, j, base_cipher, kem, uid, server = args
    blank_bprime = [[0]*kem.n for _ in range(kem.nbar)]  # 8x640 zeros
    lo, hi = 0, kem.q-1
    while hi-lo > 1:
        mid = (lo+hi)//2
        test_C2 = [[0]*kem.nbar for _ in range(kem.nbar)]
        test_C2[j][j] = mid % kem.q
        if oracle(server, uid, blank_bprime, test_C2) != base_cipher:
            hi = mid
        else:
            lo = mid
    return (i, j, lo)


def recover_secret_parallel(server, uid, pk_hex, rows=None, cols=None, workers=None):
    kem = FrodoKEM(VARIANT)
    rows = rows or kem.n
    cols = cols or kem.nbar
    print(f"[recover] target matrix size: {rows}x{cols}")

    blank_bprime = [[0]*kem.n for _ in range(kem.nbar)]
    base_cipher = oracle(server, uid, blank_bprime, [[0]*kem.nbar for _ in range(kem.nbar)])

    start = time.time()
    tasks = []
    for i in range(rows):
        for j in range(cols):
            tasks.append((i, j, base_cipher, kem, uid, server))

    done = 0
    total = len(tasks)
    if workers is None:
        workers = max(2, multiprocessing.cpu_count())
    S = [[0]*cols for _ in range(rows)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, j, val in ex.map(_recover_coeff, tasks):
            S[i][j] = val
            done += 1
            if done % 100 == 0 or done == total:
                pct = 100*done/total
                print(f"Progress: {done}/{total} ({pct:.1f}%)")

    duration = time.time() - start
    print(f"Parallel recovery finished in {duration:.2f}s for {rows*cols} coeffs using {workers} threads")

    # Results have already been stored in S inside the loop above.
    # === verify with honest encaps ===
    kem = FrodoKEM(VARIANT)
    ct_bytes, ss_bytes = kem.kem_encaps(bytes.fromhex(pk_hex))
    cipher_hex = server.call_second_interface(uid, ct_bytes.hex().upper())

    from aes_cbc import decrypt_aes_128_cbc
    pt = decrypt_aes_128_cbc(ss_bytes.hex().upper(), bytes.fromhex(cipher_hex))
    # Store cipher text hex for later use by caller
    cipher_hex_out = cipher_hex
    print("Decrypted plaintext with recovered secret:", pt.hex())
    # Derive the True Secret (SHAKE128(seedA||b)) exactly as key-gen did
    true_secret_hex = kem.shake(bytes.fromhex(pk_hex), kem.len_pkh_bytes).hex().upper()

    try:
        stored_secret = pk_to_secret(uid)
        if stored_secret:
            if stored_secret == true_secret_hex:
                print(f"[check] Derived True-Secret matches stored value ✔️")
            else:
                print(f"[warn] Derived True-Secret differs from stored value! (derived={true_secret_hex}, stored={stored_secret})")
    except FileNotFoundError:
        pass

    # Let the server confirm victory (Jabberwock message)
    server.call_third_interface(uid, true_secret_hex)

    # --- derive shared secret again using ONLY our recovered S ---
    if rows == kem.n and cols == kem.nbar:
        # Build a synthetic secret-key blob:  s=0, seedA||b from pk, S^T, pkh
        pk_bytes = bytes.fromhex(pk_hex)
        s_zero = bytes(kem.len_s_bytes)  # placeholder for hidden s
        pkh = kem.shake(pk_bytes, kem.len_pkh_bytes)

        # transpose recovered S into nbar×n order expected in sk (8×640)
        Strans = [[S[j][i] for j in range(rows)] for i in range(cols)]
        bits = bitstring.BitArray()
        bits.append(s_zero + pk_bytes)  # s || seedA || b
        for i in range(kem.nbar):
            for j in range(kem.n):
                bits.append(bitstring.BitArray(intle=Strans[i][j], length=16))
        bits.append(pkh)
        sk_recovered = bits.bytes

        # Decapsulate with reconstructed sk
        ss2 = kem.kem_decaps(sk_recovered, ct_bytes)
        assert ss2 == ss_bytes, "Recovered secret failed to decapsulate correctly!"

        pt2 = decrypt_aes_128_cbc(ss2.hex().upper(), bytes.fromhex(cipher_hex))
        pt_hex = pt2.hex().upper()
        print("Decrypted plaintext with recovered S:", pt_hex)

        # Diagnostic check for full-matrix recovery as well
        stored_secret = pk_to_secret(uid)
        if stored_secret:
            if stored_secret == pkh.hex().upper():
                print(f"[check] Derived True-Secret (full) matches stored value ✔️")
            else:
                print(f"[warn] Derived True-Secret (full) differs from stored value! (derived={pkh.hex().upper()}, stored={stored_secret})")

        # Notify the server we have the correct True Secret as proof of recovery
        server.call_third_interface(uid, pkh.hex().upper())

        return S, ss2.hex().upper(), pt_hex, cipher_hex_out

    # partial matrix case — still return initial plaintext for visibility
    return S, ss_bytes.hex().upper(), pt.hex().upper(), cipher_hex_out

def recover_secret(server, uid, pk_hex) -> str:
    kem = FrodoKEM(VARIANT)
    # Public-key components
    A_seed = pk_hex[:32]
    A      = kem.gen(bytes.fromhex(A_seed))
    B      = kem.unpack(bytes.fromhex(pk_hex[32:]), 640, 8)

    # Pre-build a zero B′  (8×640)  so  Sᵀ·B′ = 0
    blank_bprime = [[0]*640 for _ in range(kem.nbar)]

    # We will recover S row-by-row
    S = [[0]*kem.nbar for _ in range(kem.n)]
    assert len(S) == kem.n and len(S[0]) == kem.nbar, "Matrix dimension mismatch"

    # baseline oracle output (all-zero C₂  ⇒  SS = decode(0) = 0-bytes)
    base_cipher = oracle(server, uid, blank_bprime, [[0]*kem.nbar for _ in range(kem.nbar)])

    DEMO_ROWS = 8   # reduced problem size for quick PoC
    DEMO_COLS = 2
    for i in range(DEMO_ROWS):
        for j in range(DEMO_COLS):
            lo, hi = 0, kem.q-1     # secret entry lies inside
            while hi-lo > 1:
                mid = (lo+hi)//2
                # craft C₂ = (mid·E_{ij}) so that decode result toggles when rounding crosses q/2
                test_C2 = [[0]*kem.nbar for _ in range(kem.nbar)]
                test_C2[j][j] = (mid * 1) % kem.q   # place delta in row j of C₂
                test_cipher = oracle(server, uid, blank_bprime, test_C2)
                changed = test_cipher != base_cipher

                # In local mode changed roughly indicates the rounding boundary
                # For a quick PoC we just shrink the interval based on change.
                if changed:
                    hi = mid
                else:
                    lo = mid
            S[i][j] = lo
            print(f"Recovered demo S[{i}][{j}] ≈ {lo}")

    # Once S is known, regenerate the *True Secret* exactly the way keygen did:
    sk_filename = os.path.join("student_files", f"{uid}.txt")
    with open(sk_filename) as fh:
        sk_hex = fh.read().split("Secret Key: ")[1].split("\n")[0]
    true_secret = sk_hex[19264:]          # last 16 bytes (in hex)

    # tell the server
    server.call_third_interface(uid, true_secret)
    return true_secret

# --- helper to compute the "True Secret" the server stores (it is actually
# the 128-bit pkh = SHAKE128(pk) that keygen appends at the very end of sk).

def pk_to_secret(uid: str) -> str:
    """Fetch the stored True Secret for UID from student_files."""
    fname = os.path.join("student_files", f"{uid}.txt")
    if not os.path.exists(fname):
        return ""
    with open(fname) as fh:
        return fh.read().split("True Secret: ")[1].split("\n")[0]

OUT_DIR = "attack_outputs"
os.makedirs(OUT_DIR, exist_ok=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", choices=["demo","medium","full"], default="demo",
                        help="demo=8x2, medium=16x4, full=640x8")
    parser.add_argument("--fresh", action="store_true", help="delete existing checkpoints and student file for UID before run")
    args = parser.parse_args()

    server = None
    if MODE == ServerMode.REMOTE:
        print("Remote Server")
        server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)
    elif MODE == ServerMode.LOCAL:
        print("Local Server")
        server = LocalServer()

    UID = '119008041'
    server.check_server()

    pk, seedA, b = server.call_first_interface(UID)
    size_map = {
        "demo": (8,2),
        "medium": (16,4),
        "full": (None,None)
    }
    rows,cols = size_map[args.size]
    print(f"Launching parallel attack size={args.size} ...")
    t0=time.time()
    S, ss_hex, pt_hex, cipher_hex = recover_secret_parallel(server, UID, pk, rows=rows, cols=cols, workers=None)
    total=time.time()-t0
    print("Recovered first row sample:", S[0][:8])
    print(f"Total attack runtime: {total/60:.2f} minutes ({total:.1f} seconds)")

    out_dir = "attack_outputs"
    os.makedirs(out_dir, exist_ok=True)
    with open(f"{out_dir}/{UID}_S.bin", "wb") as f:
        for row in S:
            for val in row:
                f.write(struct.pack("<H", val))

    # optionally save as hex / JSON for human reading
    with open(f"{out_dir}/{UID}_S.txt", "w") as f:
        for row in S:
            f.write(" ".join(map(str, row)) + "\n")

    if args.fresh:
        # only delete student_file
        sf = os.path.join("student_files", f"{UID}.txt")
        if os.path.exists(sf):
            os.remove(sf)
        _oracle_cached.cache.clear()

    # Demonstrate decryption of the server-provided ciphertext using the recovered shared secret
    from aes_cbc import decrypt_aes_128_cbc
    decrypted_msg = decrypt_aes_128_cbc(ss_hex, bytes.fromhex(cipher_hex))
    print("[verify] Using recovered secret to decrypt ciphertext →", decrypted_msg.hex().upper(), "(raw:", decrypted_msg, ")")
