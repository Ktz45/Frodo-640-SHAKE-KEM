import os
import struct
from frodokem import FrodoKEM
import argparse
from typing import Tuple, Optional

VARIANT = "FrodoKEM-640-SHAKE"
KEM = FrodoKEM(VARIANT)

EXPECTED_ROWS = KEM.n        # 640
EXPECTED_COLS = KEM.nbar     # 8
EXPECTED_INTS = EXPECTED_ROWS * EXPECTED_COLS  # 5120
EXPECTED_BYTES = EXPECTED_INTS * 2            # 10240


def load_S_bin(path: str) -> Tuple[list[list[int]], int, int]:
    """Load a binary matrix file produced by driver (little-endian 16-bit ints)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) % 2:
        raise ValueError("S.bin length must be even (16-bit ints)")
    ints = list(struct.unpack("<" + "H"*(len(data)//2), data))
    # Try to infer dimensions: prefer EXPECTED_COLS (8) as fastest-varying (row-major order)
    #   driver writes row by row -> rows × cols order.
    cols_guess = EXPECTED_COLS if len(ints) % EXPECTED_COLS == 0 else None
    if cols_guess is None:
        # fallback to square root if perfect square
        import math
        n = int(math.isqrt(len(ints)))
        if n*n == len(ints):
            cols_guess = n
    if cols_guess is None:
        cols_guess = len(ints)   # one long row
    rows = len(ints)//cols_guess
    matrix = [ints[r*cols_guess:(r+1)*cols_guess] for r in range(rows)]
    return matrix, rows, cols_guess


def analyse_S(matrix: list, rows: int, cols: int):
    import statistics
    flat = [x for row in matrix for x in row]
    print(f"Loaded S matrix dimensions: {rows}×{cols} ({len(flat)} coefficients)")
    print(f"Expected full dimensions   : {EXPECTED_ROWS}×{EXPECTED_COLS} ({EXPECTED_INTS} coefficients)")
    if len(flat) == EXPECTED_INTS:
        print("\n✅ SIZE MATCHES expected full secret matrix.")
    else:
        print("\n⚠️  SIZE MISMATCH – this is only a partial recovery!")
    print("Value statistics (mod q):")
    print(f"  min={min(flat)}, max={max(flat)}, mean={statistics.mean(flat):.2f}")


def try_reconstruct_sk(matrix: list[list[int]], pk_hex: str):
    """Attempt to reconstruct and verify the secret key from a FULL S matrix and public key."""
    if not matrix:
        print("Skipping secret-key reconstruction because matrix was not loaded.")
        return
    if len(matrix) != EXPECTED_ROWS or len(matrix[0]) != EXPECTED_COLS:
        print("Skipping secret-key reconstruction because matrix is incomplete.")
        return
    # Re-build secret key as driver does (s=0 || pk || S^T || pkh)
    import bitstring, hashlib
    pk_bytes = bytes.fromhex(pk_hex)
    s_zero = bytes(KEM.len_s_bytes)
    pkh = KEM.shake(pk_bytes, KEM.len_pkh_bytes)
    # transpose S
    Strans = [[matrix[j][i] for j in range(EXPECTED_ROWS)] for i in range(EXPECTED_COLS)]
    bits = bitstring.BitArray()
    bits.append(s_zero + pk_bytes)
    for i in range(EXPECTED_COLS):
        for j in range(EXPECTED_ROWS):
            bits.append(bitstring.BitArray(intle=Strans[i][j] % KEM.q, length=16))
    bits.append(pkh)
    sk_bytes = bits.bytes
    # test by encapsulating new ciphertext
    ct, ss_enc = KEM.kem_encaps(pk_bytes)
    ss_dec = KEM.kem_decaps(sk_bytes, ct)
    if ss_enc == ss_dec:
        print("\n✅ Secret-key reconstruction verifies: decapsulation matches encapsulation.")
    else:
        print("\n❌ Secret-key reconstruction FAILED: derived secret mismatch.")

    # Also print the pkh derived from the provided pk for comparison
    pkh_derived = pkh.hex().upper()
    print(f"Derived True Secret (pkh from pk) = {pkh_derived}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse output of FrodoKEM attack recovery.")
    parser.add_argument("uid", help="UID used during attack (to locate files)")
    parser.add_argument("--dir", default="attack_outputs", help="Directory where *_S.bin lives")
    parser.add_argument("--pk", help="Public key hex (optional – if omitted, read from student_files)")
    args = parser.parse_args()

    S_path = os.path.join(args.dir, f"{args.uid}_S.bin")
    matrix: Optional[list[list[int]]] = None
    rows, cols = 0, 0
    try:
        matrix, rows, cols = load_S_bin(S_path)
        analyse_S(matrix, rows, cols)
    except FileNotFoundError:
        print(f"⚠️  Could not find {S_path}. Proceeding without matrix analysis.")
    except Exception as e:
        print(f"Error loading or analyzing {S_path}: {e}")
        # Decide if you want to exit or continue
        # exit(1) # Option to exit if S loading is critical

    # --- PK Handling ---
    # fetch pk from student_files if not supplied
    if not args.pk:
        sf_path = os.path.join("student_files", f"{args.uid}.txt")
        if not os.path.exists(sf_path):
            print("Could not find student file to extract public key; specify --pk manually to continue SK verification.")
        else:
            with open(sf_path) as fh:
                content = fh.read()
            args.pk = content.split("Public Key: ")[1].split("\n")[0]

    # --- SK Reconstruction (if matrix and pk available) ---
    if matrix and args.pk:
        try_reconstruct_sk(matrix, args.pk)
    elif not matrix and args.pk:
        print("\nMatrix not loaded, cannot attempt full SK reconstruction.")
        # Still print derived pkh for comparison below
        pk_bytes = bytes.fromhex(args.pk)
        pkh_derived = KEM.shake(pk_bytes, KEM.len_pkh_bytes).hex().upper()
        print(f"Derived True Secret (pkh from pk) = {pkh_derived}")
    elif not args.pk:
        print("\nPublic key not available, cannot attempt SK reconstruction or pkh derivation.")


    # === Compare with stored True Secret if available ===
    sf_path = os.path.join("student_files", f"{args.uid}.txt")
    if os.path.exists(sf_path):
        with open(sf_path) as fh:
            for line in fh:
                if line.startswith("True Secret: "):
                    stored_true = line.split("True Secret: ")[1].strip().upper() # Read full line
                    break
            else:
                stored_true = ""
        if stored_true:
            print(f"\nStored True Secret          : {stored_true}")
            # Recompute pkh from pk as reference, IF pk is available
            if args.pk:
                recomputed_pkh = KEM.shake(bytes.fromhex(args.pk), KEM.len_pkh_bytes).hex().upper()
                print(f"Recomputed True Secret (pkh): {recomputed_pkh}")
                # Compare stored secret with the RECOMPUTED pkh
                if len(stored_true) == len(recomputed_pkh): # Basic length check for pkh comparison
                    print("✔︎ Match: Stored True Secret == Recomputed pkh" if stored_true == recomputed_pkh else "✘ Mismatch: Stored True Secret != Recomputed pkh")
                else:
                    print("ℹ️  Stored True Secret format differs from standard pkh, cannot directly compare.")
                    # Optional: Compare with derived from SK reconstruction if matrix was loaded
                    # if matrix and len(matrix) == EXPECTED_ROWS and len(matrix[0]) == EXPECTED_COLS:
                    #    # This comparison might already be done in try_reconstruct_sk if needed
                    #    pass
            else:
                print("Cannot recompute pkh for comparison as public key is missing.")
        else:
            print("Could not locate True Secret in student file.")
    else:
        print("Student file not found for additional validation.") 