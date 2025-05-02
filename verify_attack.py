import numpy as np
import argparse
import os
import logging
import bitstring

from frodokem import FrodoKEM
from local_server import LocalServer

# --- Constants ---
VARIANT = "FrodoKEM-640-SHAKE"
DEFAULT_UID = '119008041'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("VerifyAttack")

def load_student_data(uid):
    """Loads pk_hex and sk_hex from the student file."""
    filename = os.path.join('student_files', f"{uid}.txt")
    log.info(f"Loading data from student file: {filename}")
    if not os.path.exists(filename):
        log.error(f"Student file not found: {filename}")
        return None, None
    try:
        with open(filename, 'r') as file:
            content = file.read()
            pk_hex = content.split('Public Key: ')[1].split('\n')[0]
            sk_hex = content.split('Secret Key: ')[1].split('\n')[0]
            log.info("Successfully loaded PK and SK hex.")
            return pk_hex, sk_hex
    except Exception as e:
        log.error(f"Error reading or parsing student file {filename}: {e}")
        return None, None

def parse_true_S(kem: FrodoKEM, sk_hex: str) -> np.ndarray | None:
    """Parses the true S matrix from the full secret key hex."""
    log.info("Parsing true S matrix from secret key hex...")
    try:
        sk_bytes = bytes.fromhex(sk_hex)
        if len(sk_bytes) != kem.len_sk_bytes:
             log.error(f"SK length mismatch in data: {len(sk_bytes)} vs expected {kem.len_sk_bytes}")
             return None

        # Calculate offset and length for S^T based on KEM parameters
        offset = kem.len_s_bytes + kem.len_seedA_bytes + int(kem.D * kem.n * kem.nbar / 8)
        length = int(kem.n * kem.nbar * 16 / 8)
        
        if offset + length > len(sk_bytes):
            log.error("Calculated offset/length for S^T exceeds secret key bounds.")
            return None
            
        Sbytes_stream = bitstring.ConstBitStream(sk_bytes[offset : offset + length])

        Stransposed = [[0 for _ in range(kem.n)] for _ in range(kem.nbar)]
        for i in range(kem.nbar):
            for j in range(kem.n):
                # Read as signed 16-bit little-endian
                # Frodo spec uses signed integers for S, E internally.
                # Need to read correctly if values can be negative. Check kem_keygen.
                # If kem_keygen samples using Frodo.Sample which returns signed values,
                # and stores them directly, we might need `intle:16`.
                # Assuming uintle for now based on original parsing.
                Stransposed[i][j] = Sbytes_stream.read('intle:16') # Use intle:16 for signed
        
        # Transpose S^T to get S (n x nbar)
        S_true_list = [[Stransposed[j][i] for j in range(kem.nbar)] for i in range(kem.n)]
        S_true_np = np.array(S_true_list, dtype=np.int64) # Use int64 for potential negative values
        log.info(f"Successfully parsed true S matrix ({S_true_np.shape}).")
        return S_true_np
            
    except Exception as e:
        log.error(f"Error parsing true S from secret key hex: {e}")
        return None

def verify_with_api(uid, pkh_hex):
    """Calls the 3rd interface with the calculated pkh."""
    log.info("--- Verifying via API (3rd Interface) --- ")
    try:
        # Simulate server interaction locally
        server = LocalServer(determ=True) # determ=True to ensure it reads the existing file
        log.info(f"Calling 3rd interface with pkh: {pkh_hex}")
        server.call_third_interface(uid, pkh_hex)
        # Output from call_third_interface is printed to stdout by the function itself
    except FileNotFoundError:
        log.error(f"Cannot verify with API: Student file for UID {uid} not found.")
    except Exception as e:
        log.error(f"Error calling 3rd interface: {e}")

def main():
    parser = argparse.ArgumentParser(description="Verify a recovered FrodoKEM S matrix.")
    parser.add_argument("recovered_s_file", help="Path to the .npy file containing the recovered S matrix.")
    parser.add_argument("-u", "--uid", type=str, default=DEFAULT_UID, help="User ID corresponding to the student file.")
    args = parser.parse_args()

    # --- Load Recovered S ---
    if not os.path.exists(args.recovered_s_file):
        log.error(f"Recovered S file not found: {args.recovered_s_file}")
        return
    try:
        log.info(f"Loading recovered S from: {args.recovered_s_file}")
        S_recovered_np = np.load(args.recovered_s_file)
        log.info(f"Recovered S matrix shape: {S_recovered_np.shape}")
        if -999 in S_recovered_np:
            log.warning("Recovered S matrix contains placeholder (-999) values. Comparison/verification will likely fail.")
    except Exception as e:
        log.error(f"Error loading recovered S file: {e}")
        return

    # --- Load True Data ---
    kem = FrodoKEM(VARIANT)
    pk_hex, sk_hex = load_student_data(args.uid)
    if pk_hex is None or sk_hex is None:
        return
    S_true_np = parse_true_S(kem, sk_hex)
    if S_true_np is None:
        return
        
    if S_recovered_np.shape != S_true_np.shape:
        log.error(f"Shape mismatch! Recovered: {S_recovered_np.shape}, True: {S_true_np.shape}")
        return

    # --- 1. Direct Matrix Comparison ---
    log.info("--- Comparing Recovered S with True S --- ")
    are_equal = np.array_equal(S_recovered_np, S_true_np)
    if are_equal:
        log.info("SUCCESS: Recovered S matrix exactly matches the true S matrix!")
    else:
        log.error("FAILURE: Recovered S matrix does NOT exactly match the true S matrix.")
        # Optional: Print differences
        diff_indices = np.where(S_recovered_np != S_true_np)
        num_diff = len(diff_indices[0])
        log.error(f"  Found {num_diff} differing elements.")
        if num_diff < 20: # Print first few differences if not too many
             for i in range(num_diff):
                  r, c = diff_indices[0][i], diff_indices[1][i]
                  log.error(f"    Mismatch at S[{r}][{c}]: Recovered={S_recovered_np[r,c]}, True={S_true_np[r,c]}")

    # --- 2. API Verification (using pkh) ---
    log.info("Calculating PKH for API verification...")
    try:
        pk_bytes = bytes.fromhex(pk_hex)
        pkh = kem.shake(pk_bytes, kem.len_pkh_bytes)
        log.info(f"Calculated PKH: {pkh.hex().upper()}")
        verify_with_api(args.uid, pkh.hex().upper())
    except Exception as e:
        log.error(f"Error during PKH calculation or API call: {e}")

    # --- 3. Decapsulation Check ---
    # Reuse verify_solution logic (adapted slightly)
    log.info("--- Performing Test Decapsulation with Recovered S --- ")
    try:
        log.info("Generating test ciphertext/shared secret...")
        ct_test_bytes, ss_test_bytes = kem.kem_encaps(pk_bytes)
        log.info(f"Test SS: {ss_test_bytes.hex().upper()}")
        
        log.info("Reconstructing SK bytes using RECOVERED S...")
        # Need to reconstruct sk_bytes with the recovered S
        s_zero = bytes(kem.len_s_bytes) # Placeholder 's'
        S_recovered_list = S_recovered_np.tolist() # Convert numpy array back if needed
        S_rec_transposed = [[S_recovered_list[j][i] for j in range(kem.n)] for i in range(kem.nbar)]
        sk_rec_bits = bitstring.BitArray()
        sk_rec_bits.append(s_zero + pk_bytes) # s || seedA || b
        for i in range(kem.nbar):
            for j in range(kem.n):
                 val = S_rec_transposed[i][j]
                 # Use signed int packing
                 sk_rec_bits.append(bitstring.BitArray(intle=val, length=16))
        sk_rec_bits.append(pkh)
        sk_rec_bytes = sk_rec_bits.bytes

        if len(sk_rec_bytes) != kem.len_sk_bytes:
             log.error(f"Constructed SK length error ({len(sk_rec_bytes)} vs {kem.len_sk_bytes}). Cannot test decaps.")
        else:
            log.info("Attempting decapsulation with reconstructed SK...")
            ss_recovered_bytes = kem.kem_decaps(sk_rec_bytes, ct_test_bytes)
            log.info(f"Recovered SS: {ss_recovered_bytes.hex().upper()}")
            if ss_recovered_bytes == ss_test_bytes:
                log.info("SUCCESS: Test decapsulation produced correct shared secret!")
            else:
                log.error("FAILURE: Test decapsulation produced incorrect shared secret.")

    except Exception as e:
        log.exception("Error during decapsulation check.")


if __name__ == "__main__":
    main() 