"""Quick offline verification script.

Loads the previously recovered S matrix for UID 119008041, builds the
secret-key guess (S^T || pkh) and asks the local server's third interface to
confirm it – no oracle queries or recomputation required.
"""

import numpy as np
import os, sys
from frodokem import FrodoKEM
from local_server import LocalServer

UID = "119008041"

print("Starting small verify test...")

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
student_file = os.path.join("student_files", f"{UID}.txt")
if not os.path.exists(student_file):
    sys.exit("student_file missing – run attack_solver once to create it.")

with open(student_file, "r") as f:
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

# --------------------------------------------------------------------
# 4. Call third interface and print server response
# --------------------------------------------------------------------
server = LocalServer(variant, determ=False)
server.call_third_interface(UID, secret_guess_hex)