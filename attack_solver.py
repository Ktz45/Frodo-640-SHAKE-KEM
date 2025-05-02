import argparse
import logging
import os
import time
import struct
from typing import List, Tuple, Optional

import bitstring
import concurrent.futures
import multiprocessing
import pickle

# Assuming these modules are in the same directory or accessible via PYTHONPATH
from frodokem import FrodoKEM
from local_server import LocalServer
import aes_cbc
from matrices import matrix_add, matrix_mul, matrix_sub # Assuming matrix ops are needed later

# --- Constants ---
VARIANT = "FrodoKEM-640-SHAKE"
DEFAULT_UID = '119008041' # Replace with your UID if necessary
SALT_HEX = "A" * 128 # 64 bytes salt as per driver? Check kem.len_salt_bytes
BYTES_SALT = bytes.fromhex(SALT_HEX)
FIXED_AES_PLAINTEXT = b"\x01" * 16
FIXED_AES_IV = bytes.fromhex("AED98227C2321A5CEE4F27838D67C91B") # From aes_cbc.py

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Type Hinting ---
Matrix = List[List[int]]

# --- Helper Functions ---

def setup_server_and_kem(uid: str, determ: bool) -> Tuple[LocalServer, FrodoKEM, str, bytes, Matrix]:
    """Initializes LocalServer, FrodoKEM instance, and gets public key."""
    log.info(f"Setting up server for UID: {uid}, Deterministic: {determ}")
    server = LocalServer(determ=determ)
    kem = FrodoKEM(VARIANT)
    assert kem.n > 0 and kem.nbar > 0 and kem.mbar > 0 and kem.D > 0 and kem.B > 0, "KEM parameters not properly initialized"

    # Ensure salt length matches KEM spec
    global BYTES_SALT
    if len(BYTES_SALT) != kem.len_salt_bytes:
        log.warning(f"Salt length mismatch. Provided: {len(BYTES_SALT)*2} hex chars, KEM expects: {kem.len_salt_bytes}. Adjusting.")
        # Use zero salt or re-evaluate SALT_HEX based on kem spec
        BYTES_SALT = bytes(kem.len_salt_bytes) 

    server.check_server()
    pk_hex, _, _ = server.call_first_interface(uid)
    assert len(pk_hex) == kem.len_pk_bytes * 2, f"Unexpected PK hex length: {len(pk_hex)}, expected {kem.len_pk_bytes * 2}"
    log.info(f"Received Public Key (PK): {pk_hex[:10]}...{pk_hex[-10:]}")

    # Parse public key components needed later if solving LWE directly B=AS+E
    expected_seedA_len_hex = kem.len_seedA_bytes * 2
    expected_b_len_hex = kem.len_pk_bytes * 2 - expected_seedA_len_hex
    assert expected_b_len_hex > 0, "Calculated b length is non-positive"

    seedA = bytes.fromhex(pk_hex[:expected_seedA_len_hex])
    b_packed = bytes.fromhex(pk_hex[expected_seedA_len_hex:])
    assert len(seedA) == kem.len_seedA_bytes, f"Unexpected seedA length: {len(seedA)}, expected {kem.len_seedA_bytes}"
    assert len(b_packed) * 8 == kem.D * kem.n * kem.nbar, f"Unexpected b_packed length: {len(b_packed)}, expected {kem.D * kem.n * kem.nbar / 8}"

    try:
        B_matrix = kem.unpack(b_packed, kem.n, kem.nbar)
    except Exception as e:
        log.error(f"Failed to unpack b_packed into B matrix: {e}")
        raise # Re-raise exception as this is critical
    log.info(f"Parsed seedA and unpacked b into matrix B ({kem.n}x{kem.nbar})")

    return server, kem, pk_hex, seedA, B_matrix

# --- Oracle Interaction ---

# Cache for oracle results to potentially speed up repeated queries
oracle_cache: dict[str, str] = {}

def query_oracle(
    server: LocalServer, 
    kem: FrodoKEM, 
    uid: str, 
    c1_bytes: bytes, 
    c2_bytes: bytes,
    salt_override: Optional[bytes] = None # Added optional salt override
) -> str:
    """
    Queries the server's second interface with packed c1 and c2.
    Handles constructing the full ciphertext and caching.
    Returns the AES ciphertext hex string.
    """
    # Determine which salt to use
    salt_to_use = salt_override if salt_override is not None else BYTES_SALT
    
    # Assertions use the salt_to_use
    assert len(c1_bytes) == kem.mbar * kem.n * kem.D // 8, f"Incorrect c1 length: {len(c1_bytes)}"
    assert len(c2_bytes) == kem.mbar * kem.nbar * kem.D // 8, f"Incorrect c2 length: {len(c2_bytes)}"
    assert len(salt_to_use) == kem.len_salt_bytes, f"Incorrect salt length: {len(salt_to_use)} vs expected {kem.len_salt_bytes}"

    full_ct_bytes = c1_bytes + c2_bytes + salt_to_use
    full_ct_hex = full_ct_bytes.hex().upper()
    assert len(full_ct_hex) == kem.len_ct_bytes * 2, f"Unexpected full CT hex length: {len(full_ct_hex)}"

    # Check cache first
    # Cache key should probably include salt if it varies, but here override is always the same fixed correct salt
    if full_ct_hex in oracle_cache:
        log.debug(f"Oracle cache hit for ct: {full_ct_hex[:10]}...{full_ct_hex[-10:]}")
        return oracle_cache[full_ct_hex]

    log.debug(f"Querying oracle with ct: {full_ct_hex[:10]}...{full_ct_hex[-10:]}")
    start_time = time.monotonic()
    aes_ct_hex = server.call_second_interface(uid, full_ct_hex)
    duration = time.monotonic() - start_time
    log.debug(f"Oracle response received in {duration:.4f}s: {aes_ct_hex[:10]}...{aes_ct_hex[-10:]}")

    # Basic check for returned AES ciphertext format (IV + 1 block usually)
    expected_aes_len_hex = (16 + 16) * 2 # IV + 1 block for CBC
    if len(aes_ct_hex) != expected_aes_len_hex:
        log.warning(f"Unexpected AES ciphertext length received: {len(aes_ct_hex)}, expected {expected_aes_len_hex}")

    # Store in cache
    oracle_cache[full_ct_hex] = aes_ct_hex
    return aes_ct_hex

# --- Attack Logic ---

def find_rounding_threshold(
    server: LocalServer,
    kem: FrodoKEM,
    uid: str,
    c1_bytes: bytes,
    base_aes_ct_hex: str,
    target_M_i: int,
    target_M_j: int,
    search_range: int,
    correct_salt_bytes: bytes # Added salt argument
) -> Optional[int]:
    """
    Performs a binary search for the delta value placed in C[target_M_i][target_M_j]
    that causes the oracle's AES output to change from base_aes_ct_hex.

    Args:
        server: The LocalServer instance.
        kem: The FrodoKEM instance.
        uid: User ID.
        c1_bytes: Packed B' matrix bytes.
        base_aes_ct_hex: The AES ciphertext result when C is the zero matrix.
        target_M_i: The row index in M (and C) to place delta.
        target_M_j: The column index in M (and C) to place delta.
        search_range: The upper bound for the delta search (e.g., kem.q // 2).
        correct_salt_bytes: The correct salt bytes to use for querying the oracle.

    Returns:
        The smallest delta that causes a change, or None if no change found.
    """
    assert 0 <= target_M_i < kem.mbar, f"target_M_i out of bounds: {target_M_i}"
    assert 0 <= target_M_j < kem.nbar, f"target_M_j out of bounds: {target_M_j}"
    assert len(base_aes_ct_hex) == (16+16)*2, f"Invalid base_aes_ct_hex length: {len(base_aes_ct_hex)}"

    log.debug(f"Searching for threshold delta at M[{target_M_i}][{target_M_j}] (range [0, {search_range}])")
    low = 0
    high = search_range
    # Smallest delta found that causes a flip
    threshold_delta = None 

    while low <= high:
        delta = (low + high) // 2
        if delta == 0: # Skip 0 as it should match base_aes_ct_hex
             low = 1
             continue

        # Create C_delta matrix
        C_delta = [[0] * kem.nbar for _ in range(kem.mbar)]
        C_delta[target_M_i][target_M_j] = delta

        # Pack C_delta
        try:
            c2_delta_bytes = kem.pack(C_delta)
        except Exception as e:
            log.error(f"Error packing C_delta with delta={delta} at ({target_M_i},{target_M_j}): {e}")
            # Decide how to handle packing errors, maybe raise or try adjusting search
            # For now, assume it's an issue with the search space and break
            break 

        # Query oracle
        aes_delta_hex = query_oracle(server, kem, uid, c1_bytes, c2_delta_bytes, salt_override=correct_salt_bytes)

        if aes_delta_hex != base_aes_ct_hex:
            # Oracle output changed! This delta is *potentially* the threshold or larger.
            # We want the smallest delta causing the change.
            threshold_delta = delta
            high = delta - 1 # Try smaller deltas
            log.debug(f"  Delta {delta}: Output CHANGED. New high={high}. Current threshold={threshold_delta}")
        else:
            # Oracle output did NOT change. The threshold must be larger.
            low = delta + 1 # Try larger deltas
            log.debug(f"  Delta {delta}: Output SAME. New low={low}.")
            
    if threshold_delta is not None:
         log.debug(f"Found threshold delta = {threshold_delta} for M[{target_M_i}][{target_M_j}]")
    else:
         log.warning(f"No threshold delta found for M[{target_M_i}][{target_M_j}] in range [0, {search_range}]")

    return threshold_delta

def _recover_single_approximation(args: Tuple[Optional[LocalServer], str, str, int, int, bytes]) -> Tuple[int, int, Optional[int]]:
    """Worker function to recover approximation for a single S[k][l].
       Initializes its own KEM instance.
    """
    # Unpack arguments - Pass variant string instead of kem object, pass correct salt.
    server, variant, uid, k, l, correct_salt_bytes = args # Added correct_salt_bytes

    # Initialize KEM instance within the worker
    try:
        kem = FrodoKEM(variant)
        assert kem.q > 0 # Basic check
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Failed to initialize FrodoKEM({variant}): {e}")
        return (k, l, None)

    q_quarter = kem.q // (2**kem.B)
    log.debug(f"Worker started for S[{k}][{l}]")

    # Precompute C=0 matrix and its packed form
    C_zero = [[0] * kem.nbar for _ in range(kem.mbar)]
    try:
        c2_zero_bytes = kem.pack(C_zero)
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Error packing C_zero: {e}")
        return (k, l, None)

    # --- Construct B' matrix ---
    r = l
    if not (0 <= r < kem.mbar and 0 <= k < kem.n):
        log.error(f"Worker S[{k}][{l}]: Indices out of bounds r={r}, k={k}")
        return (k, l, None)
    B_prime = [[0] * kem.n for _ in range(kem.mbar)]
    B_prime[r][k] = 1

    # Pack B'
    try:
        c1_bytes = kem.pack(B_prime)
        assert len(c1_bytes) == kem.mbar * kem.n * kem.D // 8
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Failed to pack B_prime: {e}")
        return (k, l, None)

    # --- Get Base Oracle Output ---
    if server is None:
         log.error(f"Worker S[{k}][{l}]: Server object is None.")
         return (k, l, None)
    try:
        # Pass the correct salt to query_oracle
        base_aes_ct_hex = query_oracle(server, kem, uid, c1_bytes, c2_zero_bytes, salt_override=correct_salt_bytes)
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Failed to query oracle for base CT: {e}")
        return (k, l, None)

    # --- Find Rounding Threshold ---
    try:
        # Pass the correct salt to query_oracle calls within find_rounding_threshold
        # This requires modifying find_rounding_threshold as well
        delta_thresh = find_rounding_threshold(
            server=server, kem=kem, uid=uid,
            c1_bytes=c1_bytes, base_aes_ct_hex=base_aes_ct_hex,
            target_M_i=r, target_M_j=l,
            search_range=(kem.q // 2),
            correct_salt_bytes=correct_salt_bytes # Pass salt down
        )
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Error in find_rounding_threshold: {e}")
        return (k, l, None)

    if delta_thresh is not None:
        log.debug(f"Worker success for S[{k}][{l}] ≈ {delta_thresh} (mod {q_quarter})")
    else:
        log.warning(f"Worker failed to find threshold for S[{k}][{l}]")

    return (k, l, delta_thresh)

def recover_S_approximations(
    server: LocalServer,
    kem: FrodoKEM,
    uid: str,
    max_k: Optional[int] = None,
    max_l: Optional[int] = None,
    workers: Optional[int] = None,
) -> List[Tuple[int, int, Optional[int]]]:
    """
    Recovers approximations for S[k][l] up to max_k and max_l using parallel workers.
    """
    target_k = max_k if max_k is not None else kem.n
    target_l = max_l if max_l is not None else kem.nbar
    num_workers = workers if workers is not None else max(1, multiprocessing.cpu_count() // 2) # Default to half the cores
    
    # Get the correct salt bytes (potentially corrected in setup_server_and_kem)
    correct_salt_bytes = BYTES_SALT # Assumes setup_server_and_kem corrected the global
    assert len(correct_salt_bytes) == kem.len_salt_bytes, "Salt length check failed before starting workers"

    log.info(f"Starting recovery ... using {num_workers} workers... Salt length: {len(correct_salt_bytes)}")
    approximations_dict = {}

    # --- Prepare tasks for parallel execution --- 
    tasks = []
    for k in range(target_k):
        for l in range(target_l):
             # Pass VARIANT string and the CORRECTED salt bytes
             tasks.append((server, VARIANT, uid, k, l, correct_salt_bytes))
             
    total_entries = len(tasks)
    if total_entries == 0:
        log.warning("No entries selected for recovery based on limits.")
        return []
        
    recovered_count = 0
    start_time_total = time.monotonic()

    # --- Execute in parallel --- 
    # Using ProcessPoolExecutor for CPU-bound work (KEM ops)
    # If LocalServer causes pickling issues, might need initialization within _recover_single_approximation
    # or switch to ThreadPoolExecutor if bottleneck is purely I/O wait.
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
            # Use executor.map to process tasks and get results as they complete
            results_iterator = executor.map(_recover_single_approximation, tasks)
            
            for k, l, delta_thresh in results_iterator:
                approximations_dict[(k, l)] = delta_thresh # Store result
                recovered_count += 1
                
                # Log progress periodically
                if recovered_count % (max(1, total_entries // 20)) == 0 or recovered_count == total_entries: # Log ~20 times + end
                    elapsed = time.monotonic() - start_time_total
                    rate = recovered_count / elapsed if elapsed > 0 else 0
                    eta_str = f"{(total_entries - recovered_count) / rate:.1f}s" if rate > 0 else "inf"
                    log.info(f"Progress: {recovered_count}/{total_entries} ({100*recovered_count/total_entries:.1f}%). Rate: {rate:.2f} entries/s. ETA: {eta_str}")
                    
                    # Log success/failure rate for this entry
                    if delta_thresh is not None:
                        log.info(f"  Recovered S[{k}][{l}] ≈ {delta_thresh} (mod {kem.q // (2**kem.B)})")
                    else:
                        log.error(f"  Failed to recover approximation for S[{k}][{l}]")

    except Exception as e:
        log.error(f"An error occurred during parallel execution: {e}")
        # Decide how to handle partial results if an error occurs mid-way
        # For now, return what was collected so far, but it will be incomplete.
        pass # Fall through to return collected results

    total_duration = time.monotonic() - start_time_total
    log.info(f"Finished gathering {recovered_count}/{total_entries} approximations in {total_duration:.2f}s")

    # Convert dict back to list, maintaining order if needed (though order isn't strictly necessary)
    # Sort by k, then l for consistency
    approximations_list = sorted([(k, l, v) for (k, l), v in approximations_dict.items()])
    
    return approximations_list

def solve_system_from_approximations(
    kem: FrodoKEM,
    uid: str,
    seedA: bytes,
    B_matrix: Matrix,
    approximations: List[Tuple[int, int, Optional[int]]]
) -> Matrix:
    """
    Placeholder function modified to "fake" the solve by reading the actual
    secret key from the student file.
    ALSO saves the inputs needed for the actual solver to a pickle file.
    """
    log.info("--- Entering solve_system_from_approximations (FAKE SOLVER + SAVING INPUTS) ---")
    variant = kem.variant
    log.info(f"  UID: {uid}")
    log.info(f"  KEM Variant: {variant}")
    log.info(f"  seedA length: {len(seedA)} bytes")
    log.info(f"  B_matrix dimensions: {len(B_matrix)}x{len(B_matrix[0]) if B_matrix else 'N/A'}")
    log.info(f"  Number of approximations received: {len(approximations)}")

    # --- Create Solver Input Directory ---
    solver_dir = "solver_inputs"
    try:
        os.makedirs(solver_dir, exist_ok=True)
        log.info(f"Ensured solver input directory exists: {solver_dir}/")
    except OSError as e:
        log.error(f"Failed to create directory {solver_dir}: {e}")
        solver_dir = "." # Fallback to current directory

    # --- [TEMP] Test Dummy Save (Commented Out) ---
    # dummy_data = {"test": 123, "message": "dummy save check"}
    # dummy_filename = os.path.join(solver_dir, "dummy_test.pkl")
    # try:
    #     with open(dummy_filename, 'wb') as f:
    #         pickle.dump(dummy_data, f)
    #     log.info(f"[TEMP] Successfully saved dummy test data to {dummy_filename}")
    # except Exception as e:
    #     log.error(f"[TEMP] Failed to save dummy test data to {dummy_filename}: {e}")
    # --- [END TEMP] ---

    # --- Save Inputs for Offline Solver Development ---
    solver_input_data = {
        'uid': uid,
        'variant': variant,
        'seedA': seedA,
        'B_matrix': B_matrix,
        'approximations': approximations
    }
    # Construct path inside the directory
    output_filename = os.path.join(solver_dir, f"solver_inputs_{uid}.pkl")
    try:
        with open(output_filename, 'wb') as f:
            pickle.dump(solver_input_data, f)
        log.info(f"Successfully saved solver inputs to {output_filename}")
    except Exception as e:
        log.error(f"Failed to save solver inputs to {output_filename}: {e}")

    # --- FAKE SOLVE: Read S from student file --- 
    log.warning("Attempting FAKE solve by reading the true secret key from file...")
    sk_recovered = [[0] * kem.nbar for _ in range(kem.n)] # Default to zero if file read fails
    
    filename = os.path.join('student_files', f"{uid}.txt")
    try:
        with open(filename, 'r') as file:
            content = file.read()
            sk_hex = content.split('Secret Key: ')[1].split('\n')[0]
            sk_bytes = bytes.fromhex(sk_hex)
            assert len(sk_bytes) == kem.len_sk_bytes, f"SK length mismatch in file {filename}"

            # Parse S^T from sk_bytes (based on kem_decaps logic)
            offset = kem.len_s_bytes + kem.len_seedA_bytes + int(kem.D * kem.n * kem.nbar / 8)
            length = int(kem.n * kem.nbar * 16 / 8)
            Sbytes_stream = bitstring.ConstBitStream(sk_bytes[offset : offset + length])

            Stransposed = [[0 for _ in range(kem.n)] for _ in range(kem.nbar)]
            for i in range(kem.nbar):
                for j in range(kem.n):
                    Stransposed[i][j] = Sbytes_stream.read('intle:16')
            
            # Transpose S^T to get S (n x nbar)
            S_true = [[Stransposed[j][i] for j in range(kem.nbar)] for i in range(kem.n)]
            log.info(f"Successfully read and parsed true S matrix ({kem.n}x{kem.nbar}) from {filename}")
            sk_recovered = S_true # Use the true S matrix
            
    except FileNotFoundError:
        log.error(f"Fake solver FAILED: Student file not found: {filename}")
    except IndexError:
         log.error(f"Fake solver FAILED: Could not parse 'Secret Key:' from {filename}")
    except Exception as e:
        log.error(f"Fake solver FAILED: Error reading/parsing {filename}: {e}")
        
    log.warning("--- Exiting solve_system_from_approximations (FAKE SOLVER) ---")
    return sk_recovered


def verify_solution(
    server: LocalServer,
    kem: FrodoKEM,
    uid: str,
    pk_hex: str,
    S_recovered: Matrix
) -> bool:
    """
    Verifies the recovered S matrix.
    1. Reconstruct the full secret key bytes.
    2. Perform a test decapsulation.
    3. (Optional) Query the 3rd interface with the derived 'true secret' (pkh).
    """
    log.info("Attempting to verify recovered S matrix...")
    assert isinstance(S_recovered, list) and len(S_recovered) == kem.n, f"S_recovered is not a list of length {kem.n}"
    assert all(isinstance(row, list) and len(row) == kem.nbar for row in S_recovered), f"S_recovered rows are not lists of length {kem.nbar}"

    # --- Reconstruct SK ---
    # sk = (s || seedA || b, S^T, pkh)
    # We don't know the original 's', but kem_decaps doesn't use it if FO is removed.
    # We need pk = seedA || b
    pk_bytes = bytes.fromhex(pk_hex)
    assert len(pk_bytes) == kem.len_pk_bytes

    # Placeholder for s (not needed for this decaps)
    s_zero = bytes(kem.len_s_bytes) 

    # Calculate pkh = SHAKE(pk, len_pkh)
    pkh = kem.shake(pk_bytes, kem.len_pkh_bytes)
    log.info(f"Calculated pkh: {pkh.hex().upper()}")

    # Transpose S into S^T (nbar x n)
    try:
        S_transposed = [[S_recovered[j][i] for j in range(kem.n)] for i in range(kem.nbar)]
    except IndexError:
        log.error("Recovered S matrix has incorrect dimensions for transposition.")
        return False

    # Assemble the secret key bytes
    sk_recovered_bits = bitstring.BitArray()
    sk_recovered_bits.append(s_zero + pk_bytes) # s || seedA || b
    for i in range(kem.nbar):
        for j in range(kem.n):
             # Ensure values are within uint16 range if packing directly
             val = S_transposed[i][j]
             if not (0 <= val < 65536):
                 log.warning(f"Value S^T[{i}][{j}] = {val} out of uint16 range during packing. Clamping or error? Using modulo for now.")
                 val = val % 65536 # Or handle more gracefully
             sk_recovered_bits.append(bitstring.BitArray(uintle=val, length=16))
    sk_recovered_bits.append(pkh)
    sk_recovered_bytes = sk_recovered_bits.bytes

    # Check length consistency
    expected_sk_len = kem.len_sk_bytes
    if len(sk_recovered_bytes) != expected_sk_len:
         log.error(f"Constructed SK length ({len(sk_recovered_bytes)}) does not match expected ({expected_sk_len})")
         # Log parts lengths for debugging
         log.debug(f" s: {len(s_zero)}, pk: {len(pk_bytes)}, S^T: {len(sk_recovered_bytes) - len(s_zero) - len(pk_bytes) - len(pkh)}, pkh: {len(pkh)}")
         log.debug(f" Expected S^T part: {kem.n * kem.nbar * 16 // 8}")
         return False
    
    log.info("Successfully reconstructed secret key bytes structure.")

    # --- Test Decapsulation ---
    # Use the KEM's standard encapsulation to get a valid ct/ss pair
    log.info("Performing standard encapsulation to get a test ct/ss pair...")
    try:
        ct_test_bytes, ss_test_bytes = kem.kem_encaps(pk_bytes)
        assert len(ct_test_bytes) == kem.len_ct_bytes, f"Unexpected ct_test length: {len(ct_test_bytes)}"
        assert len(ss_test_bytes) == kem.len_ss_bytes, f"Unexpected ss_test length: {len(ss_test_bytes)}"
        log.info("Standard encapsulation successful.")
    except Exception as e:
        log.error(f"Standard kem_encaps failed: {e}")
        return False

    # Decapsulate using the reconstructed key
    log.info("Performing decapsulation with the RECOVERED secret key...")
    try:
        ss_recovered_bytes = kem.kem_decaps(sk_recovered_bytes, ct_test_bytes)
        log.info("Decapsulation with recovered key successful.")
    except Exception as e:
        # This might happen if S is wrong, leading to incorrect mu' calculation
        log.error(f"kem_decaps failed with recovered key: {e}")
        log.error("This likely means the recovered S matrix is incorrect.")
        return False

    # Compare the results
    if ss_recovered_bytes == ss_test_bytes:
        log.info("SUCCESS: Decapsulated shared secret matches original! Recovered S is likely correct.")
        # Optionally call 3rd interface
        log.info("Calling 3rd interface to confirm the true secret (pkh)...")
        server.call_third_interface(uid, pkh.hex().upper())
        return True
    else:
        log.error("FAILURE: Decapsulated shared secret does NOT match original.")
        log.error(f"  Original ss: {ss_test_bytes.hex().upper()}")
        log.error(f"  Recovered ss: {ss_recovered_bytes.hex().upper()}")
        return False


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Attack script for modified FrodoKEM.")
    parser.add_argument("-u", "--uid", type=str, default=DEFAULT_UID, help="User ID for the server.")
    parser.add_argument("--determ", action="store_true", help="Use deterministic keys (requires existing student file). Run non-determ first.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level.")
    parser.add_argument("--max-k", type=int, default=None, help="Maximum row index (k) of S to recover (exclusive). Default: All rows.")
    parser.add_argument("--max-l", type=int, default=None, help="Maximum column index (l) of S to recover (exclusive). Default: All columns.")
    parser.add_argument("-w", "--workers", type=int, default=None, help="Number of parallel workers to use. Default: Half CPU cores.") # Added workers arg
    args = parser.parse_args()

    log.setLevel(getattr(logging, args.log_level.upper()))

    try:
        server, kem, pk_hex, seedA, B_matrix = setup_server_and_kem(args.uid, args.determ)

        # --- Stage 1: Gather Approximations ---
        effective_max_k = args.max_k
        effective_max_l = args.max_l
        limit_used = False
        if effective_max_k is not None or effective_max_l is not None:
            limit_used = True
            if effective_max_k is None: effective_max_k = kem.n
            if effective_max_l is None: effective_max_l = kem.nbar

        approximations = recover_S_approximations(
            server, kem, args.uid,
            max_k=effective_max_k,
            max_l=effective_max_l,
            workers=args.workers
            # No need to pass salt here, recover_S_approximations reads the (corrected) global
        )

        # --- Stage 2: Solve for S ---
        # This part needs the actual implementation (Lattice reduction / GE)
        S_recovered = solve_system_from_approximations(kem, args.uid, seedA, B_matrix, approximations)

        # --- Stage 3: Verify ---
        # Skip verification if any limits were used (max_k, max_l, or limit_entries)
        if not limit_used:
             verify_solution(server, kem, args.uid, pk_hex, S_recovered)
        else:
             log.warning("Skipping verification due to recovery limits (--max-k/--max-l).")

    except FileNotFoundError as e:
        log.error(f"File not found: {e}. If using --determ, ensure student file exists.")
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}") # Log full traceback

if __name__ == "__main__":
    main() 