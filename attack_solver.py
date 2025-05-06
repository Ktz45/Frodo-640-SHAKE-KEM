import logging
import os
import time
import struct
from typing import List, Tuple, Optional
import io # Added for capturing stdout
import contextlib # Added for capturing stdout

import numpy as np
import fpylll
import concurrent.futures
import multiprocessing
import time
import pickle

import bitstring

# Assuming these modules are in the same directory or accessible via PYTHONPATH
from frodokem import FrodoKEM
# from local_server import RemoteServer
import aes_cbc
from matrices import matrix_add, matrix_mul, matrix_sub
import solve_system_testing # Assuming matrix ops are needed later

# ==== Copied from driver.py ====
from frodokem import FrodoKEM
from remote_server import RemoteServer
# from local_server import RemoteServer
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
# ===============================

# --- Configuration Constants ---
VARIANT = "FrodoKEM-640-SHAKE"
# UID = '119008041' # User ID for the server. Was DEFAULT_UID
UID = '116606028' # User ID for the server. Was DEFAULT_UID

DETERM = False # Use deterministic keys (requires existing student file). Was --determ flag.
LOG_LEVEL = "INFO" # Logging level. Was --log-level argument.
MAX_K = None # Maximum row index (k) of S to recover. Was --max-k argument.
MAX_L = None # Maximum column index (l) of S to recover. Was --max-l argument.
WORKERS = None # Number of parallel workers for approximation gathering. Was --workers argument. Set to None for default (half CPU).

# --- Internal Constants ---
SALT_HEX = "0" * 64 # Correct length: 64 hex chars = 32 bytes
# BYTES_SALT = bytes.fromhex(SALT_HEX)
FIXED_AES_PLAINTEXT = b"\x01" * 16


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


# --- Logging Setup ---
# Configure logging level based on the constant
log_level_numeric = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(level=log_level_numeric,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Type Hinting ---
Matrix = List[List[int]]

# --- Helper Functions ---

def setup_server_and_kem(uid: str, determ: bool) -> Tuple[RemoteServer, FrodoKEM, str, bytes, Matrix]:
    """Initializes RemoteServer, FrodoKEM instance, and gets public key."""
    log.info(f"Setting up server for UID: {uid}, Deterministic: {determ}")
    # server = RemoteServer(VARIANT, determ=determ)
    server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)
    kem = FrodoKEM(VARIANT)
    assert kem.n > 0 and kem.nbar > 0 and kem.mbar > 0 and kem.D > 0 and kem.B > 0, "KEM parameters not properly initialized"

    # Ensure salt length matches KEM spec
    global BYTES_SALT
    if len(BYTES_SALT) != kem.len_salt_bytes:
        # log.warning(f"Salt length mismatch. Provided: {len(BYTES_SALT)*2} hex chars, KEM expects: {kem.len_salt_bytes}. Adjusting.")
        # BYTES_SALT = bytes(kem.len_salt_bytes)
        raise ValueError(f"Salt length mismatch. Provided: {len(BYTES_SALT)*2} hex chars, KEM expects: {kem.len_salt_bytes}. Correct SALT_HEX constant.")

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
    server: RemoteServer, 
    kem: FrodoKEM, 
    uid: str, 
    c1_bytes: bytes, 
    c2_bytes: bytes,
) -> str:
    """
    Queries the server's second interface with packed c1 and c2.
    Handles constructing the full ciphertext and caching.
    Returns the AES ciphertext hex string.
    """
    # Determine which salt to use
    salt_to_use = BYTES_SALT
    
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
    server: RemoteServer,
    kem: FrodoKEM,
    uid: str,
    c1_bytes: bytes,
    base_aes_ct_hex: str,
    target_M_i: int,
    target_M_j: int,
    search_range: int,
) -> Optional[int]:
    """
    Performs a binary search for the delta value placed in C[target_M_i][target_M_j]
    that causes the oracle's AES output to change from base_aes_ct_hex.

    Args:
        server: The RemoteServer instance.
        kem: The FrodoKEM instance.
        uid: User ID.
        c1_bytes: Packed B' matrix bytes.
        base_aes_ct_hex: The AES ciphertext result when C is the zero matrix.
        target_M_i: The row index in M (and C) to place delta.
        target_M_j: The column index in M (and C) to place delta.
        search_range: The upper bound for the delta search

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
        aes_delta_hex = query_oracle(server, kem, uid, c1_bytes, c2_delta_bytes)

        # Check if changed AND if this delta is the smallest found so far
        if aes_delta_hex != base_aes_ct_hex and (threshold_delta is None or delta < threshold_delta):
            # Oracle output changed! This delta is *potentially* the threshold or larger.
            # We want the smallest delta causing the change.
            threshold_delta = delta
            high = delta - 1 # Try smaller deltas
            log.debug(f"  Delta {delta}: Output CHANGED. New high={high}. Current threshold={threshold_delta}")
        else:
            # Oracle output did NOT change OR a smaller threshold was already found.
            # The actual threshold must be larger than current delta (if unchanged)
            # or we stick with the smaller threshold already found.
            low = delta + 1 # Try larger deltas
            log.debug(f"  Delta {delta}: Output SAME or smaller threshold exists. New low={low}.")
            
    if threshold_delta is not None:
        log.debug(f"Found threshold delta = {threshold_delta} for M[{target_M_i}][{target_M_j}]")
    else:
        log.warning(f"No threshold delta found for M[{target_M_i}][{target_M_j}] in range [0, {search_range}]")
        raise Exception(f"No threshold delta found for M[{target_M_i}][{target_M_j}] in range [0, {search_range}]")

    return threshold_delta

def _recover_single_approximation(args: Tuple[str, str, int, int]) -> Tuple[int, int, Optional[int]]:
    """Worker function executed in a separate process.
       It creates its own RemoteServer and FrodoKEM instances to avoid pickling
       issues with lambdas inside those objects.
    """
    variant, uid, k, l = args

    # Instantiate a fresh RemoteServer (reads existing student file)  
    # server = RemoteServer(variant, determ=False)
    server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)

    # Initialize KEM instance within the worker
    try:
        kem = FrodoKEM(variant)
        assert kem.q > 0  # Basic check
        # Ensure l < mbar so r=l is valid row index in M/C matrices
        assert l < kem.mbar, (
            f"Worker S[{k}][{l}]: Column index l={l} >= mbar={kem.mbar}, invalid target_M_i."
        )
    except Exception as e:
        # Use print because logging from child process may not propagate
        print(f"[Worker {k},{l}] Error initialising FrodoKEM: {e}")
        return (k, l, None)

    # q_quarter = 32768 // 4
    q_quarter = kem.q // 4
    log.debug(f"Worker started for S[{k}][{l}] with q_quarter={q_quarter}")

    # Precompute C=0 matrix and its packed form
    C_zero = [[0] * kem.nbar for _ in range(kem.mbar)]
    try:
        c2_zero_bytes = kem.pack(C_zero)
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Error packing C_zero: {e}")
        raise Exception(f"Worker S[{k}][{l}]: Error packing C_zero: {e}")

    # --- Construct B' matrix ---
    r = l
    if not (0 <= r < kem.mbar and 0 <= k < kem.n):
        log.error(f"Worker S[{k}][{l}]: Indices out of bounds r={r}, k={k}")
        raise Exception(f"Worker S[{k}][{l}]: Indices out of bounds r={r}, k={k}")
    B_prime = [[0] * kem.n for _ in range(kem.mbar)]
    B_prime[r][k] = 1

    # Pack B'
    try:
        c1_bytes = kem.pack(B_prime)
        assert len(c1_bytes) == kem.mbar * kem.n * kem.D // 8
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Failed to pack B_prime: {e}")
        raise Exception(f"Worker S[{k}][{l}]: Failed to pack B_prime: {e}")

    # --- Get Base Oracle Output ---
    try:
        base_aes_ct_hex = query_oracle(server, kem, uid, c1_bytes, c2_zero_bytes)
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Failed to query oracle for base CT: {e}")
        raise Exception(f"Worker S[{k}][{l}]: Failed to query oracle for base CT: {e}")

    # --- Find Rounding Threshold ---
    try:
        delta_thresh = find_rounding_threshold(
            server=server, 
            kem=kem, 
            uid=uid,
            c1_bytes=c1_bytes, 
            base_aes_ct_hex=base_aes_ct_hex,
            target_M_i=r, 
            target_M_j=l,
            search_range=(kem.q // 4),
        )
    except Exception as e:
        log.error(f"Worker S[{k}][{l}]: Error in find_rounding_threshold: {e}")
        raise Exception(f"Worker S[{k}][{l}]: Error in find_rounding_threshold: {e}")

    if delta_thresh is not None:
        log.debug(f"Worker success for S[{k}][{l}] ≈ {delta_thresh} (mod {q_quarter})")
    else:
        log.warning(f"Worker failed to find threshold for S[{k}][{l}]")
        raise Exception(f"Worker failed to find threshold for S[{k}][{l}]")

    return (k, l, delta_thresh)

def recover_S_approximations(
    server: RemoteServer,
    kem: FrodoKEM,
    uid: str,
    max_k: Optional[int] = None,
    max_l: Optional[int] = None,
    workers: Optional[int] = None
) -> List[Tuple[int, int, Optional[int]]]:
    """
    Recovers approximations for S[k][l] up to max_k and max_l using parallel workers.
    """
    target_k = max_k if max_k is not None else kem.n
    target_l = max_l if max_l is not None else kem.nbar
    num_workers = workers if workers is not None else max(1, multiprocessing.cpu_count())
    
    # Get the correct salt bytes (potentially corrected in setup_server_and_kem)
    correct_salt_bytes = BYTES_SALT
    assert len(correct_salt_bytes) == kem.len_salt_bytes, "Salt length check failed before starting workers"

    log.info(f"Starting recovery using {num_workers} workers... Salt length: {len(correct_salt_bytes)}")
    approximations_dict = {}

    # --- Prepare tasks for parallel execution --- 
    tasks = []
    log.info(f"Targeting entries up to k={target_k-1}, l={target_l-1}")
    for k in range(target_k):
        for l in range(target_l):
             tasks.append((VARIANT, uid, k, l))
             
    total_entries = len(tasks)
    if total_entries == 0:
        log.warning("No entries selected for recovery based on limits.")
        return []
        
    recovered_count = 0
    start_time_total = time.monotonic()

    # --- Execute in parallel --- 
    # Use threads to avoid pickling RemoteServer (which contains an unpicklable lambda).
    # The cryptographic heavy-lifting is Python-level anyway, so GIL contention is minor
    # compared to the I/O bound oracle queries.
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
                        log.info(f"  Recovered S[{k}][{l}] ≈ {delta_thresh} (mod {kem.q // 4})")
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
    Saves the inputs needed for the actual solver called at the end of this function
    (solve_system_testing.py) to a pickle file.
    Returns a dummy matrix.
    """
    log.info("--- Entering solve_system_from_approximations (PLACEHOLDER - SAVING INPUTS) ---")
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
        raise OSError(f"Failed to create directory {solver_dir}: {e}")

    # --- Read True S from student file --- 
    S_true = None
    log.info("Attempting to read true S from student file for debugging...")
    true_s_filename = os.path.join('student_files', f"{uid}.txt")
    try:
        with open(true_s_filename, 'r') as file:
            content = file.read()
            sk_hex = content.split('Secret Key: ')[1].split('\n')[0]
            sk_bytes = bytes.fromhex(sk_hex)
            assert len(sk_bytes) == kem.len_sk_bytes, f"SK length mismatch in file {true_s_filename}"

            offset = kem.len_s_bytes + kem.len_seedA_bytes + int(kem.D * kem.n * kem.nbar / 8)
            length = int(kem.n * kem.nbar * 16 / 8)
            Sbytes_stream = bitstring.ConstBitStream(sk_bytes[offset : offset + length])

            Stransposed = [[0 for _ in range(kem.n)] for _ in range(kem.nbar)]
            for i in range(kem.nbar):
                for j in range(kem.n):
                    Stransposed[i][j] = Sbytes_stream.read('intle:16')
            
            S_true_read = [[Stransposed[j][i] for j in range(kem.nbar)] for i in range(kem.n)]
            log.info(f"Successfully read and parsed true S matrix from {true_s_filename}")
            S_true = S_true_read # Assign if successful
            
    except FileNotFoundError:
        log.error(f"Could not find student file: {true_s_filename}. Cannot include true S in solver inputs.")
    except Exception as e:
        log.error(f"Error reading/parsing true S from {true_s_filename}: {e}")

    # --- Save Inputs for Offline Solver --- 
    solver_input_data = {
        'uid': uid,
        'variant': variant,
        'seedA': seedA,
        'B_matrix': B_matrix,
        'approximations': approximations,
        'S_true': S_true,  # may be None if not available
    }
    output_filename = os.path.join(solver_dir, f"solver_inputs_{uid}.pkl")
    try:
        with open(output_filename, 'wb') as f:
            pickle.dump(solver_input_data, f)
        log.info(f"Successfully saved solver inputs to {output_filename}")
    except Exception as e:
        log.error(f"Failed to save solver inputs to {output_filename}: {e}")


    # call solve_system_testing.py
    # Pass configuration using constants and set cmdline=False
    S_recovered_matrix = solve_system_testing.main(
        cmdline=False, # Call as a function, not from command line
        uid=UID, # Pass the UID constant
        cols=None, # Keep default or define constant if needed
        workers=WORKERS, # Pass the WORKERS constant
        bkz_block_size=80, # Updated starting block size to 80
        bkz_float_type='mp', # Keep default or define constant if needed
        log_level=LOG_LEVEL, # Pass the LOG_LEVEL constant
        target_col=None # Keep default or define constant if needed
    )

    return S_recovered_matrix


def verify_solution(
    server: RemoteServer,
    kem: FrodoKEM,
    uid: str,
    pk_hex: str,
    S_recovered: np.ndarray # Keep input for consistency, though not used in this logic
) -> bool:
    """
    Verifies the recovery by calling the server's third interface 
    with the calculated pkh (hash of the public key) and checking 
    its printed output for the success message.
    """
    log.info("Attempting to verify recovery via server's third interface (checking pkh)...")
    
    # Basic check on input S_recovered format (optional but good practice)
    assert isinstance(S_recovered, np.ndarray), f"S_recovered is not a NumPy array, but type {type(S_recovered)}"
    assert S_recovered.shape == (kem.n, kem.nbar), f"S_recovered has shape {S_recovered.shape}, expected ({kem.n}, {kem.nbar})"

    # Build the secret-key guess = S^T (16-bit little-endian) || pkh
    try:
        # --- pkh ---
        pk_bytes = bytes.fromhex(pk_hex)
        assert len(pk_bytes) == kem.len_pk_bytes
        pkh_bytes = kem.shake(pk_bytes, kem.len_pkh_bytes)
        pkh_hex = pkh_bytes.hex().upper()

        # --- S^T encoding ---
        S_transposed = S_recovered.T.astype(np.int16)  # shape (nbar, n)
        st_bytes = bytearray()
        for i in range(kem.nbar):
            for j in range(kem.n):
                value = int(S_transposed[i, j]) % (1 << 16)
                st_bytes += value.to_bytes(2, byteorder="little", signed=False)

        assert len(st_bytes) == kem.n * kem.nbar * 2, "Encoded S^T length mismatch"
        secret_guess_hex = st_bytes.hex().upper() + pkh_hex
        log.info(f"Built secret-key guess hex length {len(secret_guess_hex)}")
    except Exception as e:
        log.error(f"Error building secret-key guess: {e}")
        return False

    # Call the third interface and capture its output
    success_message = "And hast thou slain the Jabberwock?"
    f = io.StringIO()
    try:
        log.info("Calling third interface with secret-key guess…")
        with contextlib.redirect_stdout(f):
             server.call_third_interface(uid, secret_guess_hex)
        output = f.getvalue()
        log.debug(f"Captured output from third interface: {output.strip()}") # Log captured output for debug
        
        # Check if the specific success message is in the output
        GREEN = "\033[92m"
        RED = "\033[91m"
        RESET = "\033[0m"
        if success_message in output:
            log.info(f"{GREEN}SUCCESS: Found success message in third interface output.{RESET}")
            return True
        else:
            log.error(f"{RED}FAILURE: Success message not found in third interface output. Output was: {output.strip()}{RESET}")
            return False
            
    except Exception as e:
        # Handle exceptions during the call (e.g., FileNotFoundError)
        log.error(f"FAILURE: Exception occurred during call_third_interface: {e}")
        return False

def sanity_check_small_test_verfify():
    """Quick offline verification script.
    Loads the previously recovered S matrix for UID 119008041, builds the
    secret-key guess (S^T || pkh) and asks the local server's third interface to
    confirm it – no oracle queries or recomputation required.
    """

    import numpy as np
    import os, sys
    from frodokem import FrodoKEM
    from remote_server import RemoteServer

    UID = "116606028"

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
    # server = RemoteServer(variant, determ=False)
    server = RemoteServer(TEST_URL, first_interface, second_interface, third_interface)
    server.call_third_interface(UID, secret_guess_hex)

# --- Main Execution ---

def main():
    # Arguments are now constants defined above
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
    # elif args.mode == "local" and args.size == "small":
    #     print("Local Server, small")
    #     variant = "Small-FrodoKEM"
    #     server = RemoteServer(variant, determ=args.determ)
    # elif args.mode == "local":
    #     print("Local Server, full")
    #     server = RemoteServer(variant, determ=args.determ)
    else:
        raise ValueError("Remote Server cannot use small size")
    

    log.setLevel(log_level_numeric) # Use the numeric level set earlier

    try:
        # Use constants directly instead of args.xxx
        server, kem, pk_hex, seedA, B_matrix = setup_server_and_kem(UID, DETERM)

        # --- Stage 1: Gather Approximations ---
        effective_max_k = MAX_K
        effective_max_l = MAX_L
        limit_used = False
        if effective_max_k is not None or effective_max_l is not None:
            limit_used = True
            if effective_max_k is None: effective_max_k = kem.n
            if effective_max_l is None: effective_max_l = kem.nbar

        # Always perform a fresh oracle recovery; skip any cached pickle to avoid
        # pulling in stale / incorrect approximation data.
        log.info("Starting fresh oracle recovery for S approximations (ignoring cached results)...")
        approximations = recover_S_approximations(
            server,
            kem,
            UID,
            max_k=effective_max_k,
            max_l=effective_max_l,
            workers=WORKERS,
        )

        # --- Stage 2: Solve for S ---
        # Pass constants to the solver function call
        S_recovered = solve_system_from_approximations(kem, UID, seedA, B_matrix, approximations)

        # --- Stage 3: Verify ---
        # Skip verification if any limits were used
        if not limit_used:
             verify_solution(server, kem, UID, pk_hex, S_recovered)
        else:
             log.warning("Skipping verification due to recovery limits (MAX_K/MAX_L constants were set).")

        
        # --- Sanity Check to call the small verify test ---
        sanity_check_small_test_verfify()


    except FileNotFoundError as e:
        log.error(f"File not found: {e}. If using DETERM=True, ensure student file exists.")
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}") # Log full traceback

if __name__ == "__main__":
    main()