import numpy as np
from frodokem import FrodoKEM
import bitstring
import sys
import os
UID = "116606028"

def print_recovered_S_116606028():
    S = np.load('/home/ubuntu/Frodo-640-SHAKE-KEM/recovered_S_116606028.npy')


    # --------------------------------------------------------------------
    # 1. Load recovered S matrix (produced by solve_system_testing earlier)
    # --------------------------------------------------------------------
    npy_path = f"recovered_S_{UID}.npy"
    if not os.path.exists(npy_path):
        sys.exit(f"Recovered matrix {npy_path} not found – run the solver first.")

    S = np.load(npy_path)  # shape (640,8)

    # --------------------------------------------------------------------
    # 2. Read student file to obtain PK and variant (do NOT regenerate keys)
    # --------------------------------------------------------------------
    if not os.path.exists("/home/ubuntu/Frodo-640-SHAKE-KEM/attack_solver_elan_12_43_remote_1.log"):
        sys.exit("student_file missing – run attack_solver once to create it.")

    with open("/home/ubuntu/Frodo-640-SHAKE-KEM/attack_solver_elan_12_43_remote_1.log", "r") as f:
        txt = f.read()

    variant = txt.split("Variant: ")[1].split("\n")[0]
    pk_hex  = txt.split("Public Key: ")[1].split("\n")[0]

    # --------------------------------------------------------------------
    # 3. Compute pkh and encode S^T
    # --------------------------------------------------------------------
    kem = FrodoKEM(variant)

    pkh = kem.shake(bytes.fromhex(pk_hex), kem.len_pkh_bytes)

    S_T = S.T.astype(np.int16)
    st_bytes = bytearray()
    for i in range(kem.nbar):
        for j in range(kem.n):
            value = int(S_T[i, j]) % (1 << 16)
            st_bytes += value.to_bytes(2, byteorder="little", signed=False)

    secret_guess_hex = st_bytes.hex().upper() + pkh.hex().upper()
    assert len(st_bytes) == kem.n * kem.nbar * 2, "Encoded S^T length mismatch"

    print("Secret guess hex:")
    print(secret_guess_hex)
    

    # Print the full matrix
    np.set_printoptions(threshold=np.inf, linewidth=200)
    print("Full S matrix:")
    print(S)

print_recovered_S_116606028()
