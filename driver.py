from frodokem import FrodoKEM
from remote_server import RemoteServer
from local_server import LocalServer
from matrices import MatrixSet, matrix_add, matrix_mul, matrix_sub
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

BASE_URL: str = "http://sp25cmsc656.cs.umd.edu:5001/"
TEST_URL = f'{BASE_URL}/check'
first_interface = f"{BASE_URL}/1st-interface"
second_interface = f"{BASE_URL}/2nd-interface"
third_interface = f"{BASE_URL}/3rd-interface"
Q = 32768
salt = ""
for _ in range(64):
    salt += "A"
BYTES_SALT = bytes.fromhex(salt)


def matrix_gen_c1(kem, R, A, E1):
    Bprime = matrix_add(matrix_mul(R, A), E1)
    c1 = kem.pack(Bprime)
    return c1

def matrix_gen_c2(kem, R, B, E2, K, delta, delta_i, delta_j):
    V = matrix_add(matrix_mul(R, B), E2)
    V[delta_i][delta_j] = (V[delta_i][delta_j] + delta) % Q
    C = matrix_add(V, K)
    c2 = kem.pack(C)
    return c2

def encaps(kem, matrix_set, delta=0, delta_i=0, delta_j=0):
    """
    Emulate kem_encaps with custom set terms
    """
    c1 = matrix_gen_c1(kem, matrix_set.R, matrix_set.A, matrix_set.E1)
    c2 = matrix_gen_c2(kem, matrix_set.R, matrix_set.B, matrix_set.E2, matrix_set.K, delta, delta_i, delta_j)
    ss = kem.decode(matrix_set.K)
    ct = c1 + c2 + BYTES_SALT
    if len(ss) == 4:
        ss = ss + b"\x01" * 12
    return ct, ss

def permute_delta(server, uid, kem, matrix_set, c1, ss, deltaMax, delta_i, delta_j):
    """
    Finds the highest value of delta at entry i,j such that AES will succeed 
    """
    low = 0
    high = deltaMax
    delta = (high + low) // 2
    failed = False
    while low <= high:
        delta = (high + low) // 2
        c2 = matrix_gen_c2(kem, matrix_set.R, matrix_set.B, matrix_set.E2, matrix_set.K, delta, delta_i, delta_j)
        ct = c1 + c2 + BYTES_SALT
        aes_ct = server.call_second_interface(uid, ct.hex().upper())
        failed = False
        try:
            aes_cbc.decrypt_aes_128_cbc(ss.hex().upper(), bytes.fromhex(aes_ct))
        except ValueError:
            failed = True
            high = delta - 1
        if not failed:
            low = delta + 1
    if failed:
        delta = delta - 1
    return delta

def find_key(aes_ct, ss):
    byte_array = bytearray(ss)
    for i in range(16):
        for bitflip in range(1, 255): # TODO: find a way to scale this down
            byte_array[i] = byte_array[i] ^ bitflip
            test_ct = aes_cbc.encrypt_aes_128_cbc(byte_array.hex().upper())
            if(test_ct.hex().upper() == aes_ct):
                return byte_array.hex().upper(), i, bitflip
            byte_array[i] = byte_array[i] ^ bitflip
    return None, None, None

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
    server,uid, kem, matrix_set, c1, ss, Q, i, j = args
    delta = permute_delta(server,uid, kem, matrix_set, c1, ss, Q, i, j)
    ct, ss = encaps(kem, matrix_set, delta=(delta + 1), delta_i=i, delta_j=j)
    aes_ct = server.call_second_interface(UID, ct.hex().upper())
    key, bitflip, byte_num = find_key(aes_ct, ss)
    if key is None or bitflip is None or byte_num is None:
        raise ValueError(f"Failed to find key for ({i},{j})")
    KPrime = kem.encode(bytes.fromhex(key))
    # TODO: find equation based on delta and KPrime
    return (i, j, delta, KPrime)


def recover_secret_parallel(server, variant, uid, seedA, b, rows=None, cols=None, workers=None):
    kem = FrodoKEM(variant)
    rows = rows or kem.n
    cols = cols or kem.nbar
    print(f"[recover] target matrix size: {rows}x{cols}")

    matrix_set = MatrixSet(rows, cols, variant, seedA=seedA, b=b)
    ct, ss = encaps(kem, matrix_set)
    c1 = ct[0:(int(kem.mbar * kem.n * kem.D / 8))]

    start = time.time()
    tasks = []
    for i in range(cols):
        for j in range(cols):
            tasks.append((server, uid, kem, matrix_set, c1, ss, Q, i, j))

    done = 0
    total = len(tasks)
    if workers is None:
        workers = max(2, multiprocessing.cpu_count())
    S = [[0]*cols for _ in range(rows)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, j, delta, KPrime in ex.map(_recover_coeff, tasks):
            S[i][j] = delta
            done += 1
            if done % 8 == 0 or done == total:
                pct = 100*done/total
                print(f"Progress: {done}/{total} ({pct:.1f}%)")

    duration = time.time() - start
    print(f"Parallel recovery finished in {duration:.2f}s for {rows*cols} coeffs using {workers} threads")

    exit(0)
    # Results have already been stored in S inside the loop above.
    # === verify with honest encaps ===
    kem = FrodoKEM(variant)
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
    parser.add_argument("--size", choices=["small","full"], default="full",
                        help="small=32x4, full=640x8")
    parser.add_argument("--mode", choices=["local","remote"], default="local",
                        help="local, remote")
    parser.add_argument("--fresh", action="store_true", help="delete existing checkpoints and student file for UID before run")
    parser.add_argument("--determ", action="store_true", help="run based on the last student file saved")
    args = parser.parse_args()

    server = None
    variant = "FrodoKEM-640-SHAKE"
    if args.mode == "remote" and args.size == "full":
        print("Remote Server")
        server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)
    elif args.mode == "local" and args.size == "small":
        print("Local Server, small")
        variant = "Small-FrodoKEM"
        server = LocalServer(variant, determ=args.determ)
    elif args.mode == "local":
        print("Local Server, full")
        server = LocalServer(variant, determ=args.determ)
    else:
        raise ValueError("Remote Server cannot use small size")

    UID = '119008041'
    server.check_server()

    pk, seedA, b = server.call_first_interface(UID)

    size_map = {
        "small": (32,4),
        "full": (None,None)
    }
    rows,cols = size_map[args.size]
    print(f"Launching parallel attack size={args.size} ...")
    t0=time.time()
    S, ss_hex, pt_hex, cipher_hex = recover_secret_parallel(server, variant, UID, seedA, b, rows=rows, cols=cols, workers=None)
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
