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

    # try:
    #     # Use constants directly instead of args.xxx
    #     server, kem, pk_hex, seedA, B_matrix = setup_server_and_kem(UID, DETERM)

    #     # --- Stage 1: Gather Approximations ---
    #     effective_max_k = MAX_K
    #     effective_max_l = MAX_L
    #     limit_used = False
    #     if effective_max_k is not None or effective_max_l is not None:
    #         limit_used = True
    #         if effective_max_k is None: effective_max_k = kem.n
    #         if effective_max_l is None: effective_max_l = kem.nbar

    #     # Always perform a fresh oracle recovery; skip any cached pickle to avoid
    #     # pulling in stale / incorrect approximation data.
    #     log.info("Starting fresh oracle recovery for S approximations (ignoring cached results)...")
    #     approximations = recover_S_approximations(
    #         server,
    #         kem,
    #         UID,
    #         max_k=effective_max_k,
    #         max_l=effective_max_l,
    #         workers=WORKERS,
    #     )

    #     # --- Stage 2: Solve for S ---
    #     # Pass constants to the solver function call
    #     S_recovered = solve_system_from_approximations(kem, UID, seedA, B_matrix, approximations)

    #     # --- Stage 3: Verify ---
    #     # Skip verification if any limits were used
    #     if not limit_used:
    #          verify_solution(server, kem, UID, pk_hex, S_recovered)
    #     else:
    #          log.warning("Skipping verification due to recovery limits (MAX_K/MAX_L constants were set).")

        
    #     # --- Sanity Check to call the small verify test ---
    #     sanity_check_small_test_verfify()


    # except FileNotFoundError as e:
    #     log.error(f"File not found: {e}. If using DETERM=True, ensure student file exists.")
    # except Exception as e:
    #     log.exception(f"An unexpected error occurred: {e}") # Log full traceback


    
    rec_secret_key = "0200FCFF00000000FDFF04000400010005000900FCFF03000200F8FF010002000100FFFF01000100FFFFFFFF020003000200FDFFFDFF0200000003000000010001000100FDFF000001000700FFFF02000100050004000200FFFFFDFF02000000FCFFFEFF06000100FAFF0400FFFFFEFFFDFFFDFFFEFF0200FFFF0400FFFF01000000FDFF020002000100FCFF02000300020001000100FBFFFDFFFFFFFFFF00000400FFFF05000000FDFFFDFF0200FEFFFDFFFAFF02000500FBFFFDFF0100FDFFFFFF010002000100FBFFFDFFFEFF0100FFFFFBFF0300FBFFFFFF0200FFFF0400FFFF010005000200FFFFFCFF0200FEFF040002000500FBFF0400FBFFFAFFFDFF0300FEFFFFFFFCFF0500FDFFFFFFFDFF02000200FBFF0000FFFFFCFFF7FFFEFF0300020002000400030003000200FEFF0000FFFF02000000FEFF01000400FEFF02000100FFFF0300FFFFFEFF010001000300FCFFFEFF000001000600FBFF0100FFFF000002000200FAFFF8FFFEFF04000000FFFFFEFF0000FDFF00000000FCFF010003000000FAFFFCFFFFFF0400FFFF0300020002000000010003000400FDFF0500FFFF0300FDFF0400FCFF0300FDFFFEFFFFFF0100FBFF010002000000FFFF06000200FEFFFFFF0400030003000000FEFF0400FDFF00000100FEFF0000030003000100FEFF06000000FDFF0100FBFFFCFF04000000FFFF0600FFFF0600FDFF0000FFFF0000FFFF010000000100FDFF050000000600FDFF02000300FCFF0100FFFFFFFF060002000300FFFFFBFF03000800FFFFFFFFFDFFFFFFFFFFFFFF0200FDFF0100F9FF01000500FCFF0000FFFF0300FDFF0100FEFFFFFF0100010000000000FCFFFDFFFDFFFDFF020000000200FAFF02000300FCFF02000400FDFFFFFF05000500FEFF0400FEFF030000000100FFFF0700FEFFFEFF0000010001000300FEFFFDFFFEFF06000300010001000400FDFF01000300FFFF0200010000000100FFFFFCFF05000200FEFFFEFFFFFF0200FCFF00000300FCFFFFFF0400FEFFFEFFFDFFFBFF00000000000000000000FEFF0000020002000000FFFF0000FEFF0200FFFF0200FFFF00000100FFFF0300FEFFFCFFFEFF0200FDFFFEFFFEFF00000100FFFF0500FCFF0000FEFF0100FFFF02000100030001000100FFFF000003000300F9FF000002000100FFFF02000300FFFFFBFFFEFF0100FDFF030002000000FEFF0000000002000100FEFFFBFF02000100FCFF0400FFFFFEFFFDFFFEFF050001000000FDFF050001000200FEFF00000000FDFF0200FFFF010001000100FEFF0000FDFF0100FDFFFFFFFCFFFCFFFBFF0700FEFF02000000000003000200FFFFFCFFFEFF00000600030001000700FEFF0200FFFF02000500FCFFFFFFFDFF0100FEFF0500FBFF0000FFFFFDFF0600FEFFFBFF01000200FFFF030002000000FEFF03000100FCFF0200FFFFFEFF0000050003000400FFFFFFFF03000500FFFF0100FDFF0000FBFF02000100FCFFFBFF00000600FDFF020002000400FDFF0300FFFF0200FFFF0100FFFFFFFF05000300FBFF04000400FFFF0200FEFF000001000300010002000000FDFF0300FEFF0000FDFF00000100050003000200FCFF0100FAFF0100FEFFFEFFFDFF0200FFFF0200FBFF00000300FFFFFAFF0000FEFF0100FDFFFCFF0200030001000500FFFF010000000100FEFF0000F9FF0100FEFFFEFFFEFF01000000FFFFFCFF00000000FBFF04000400FFFFFAFF0200FDFF0200FDFF02000000010001000500FEFFFFFF0200FDFFFFFF020004000100FDFF0100FEFF0000FEFF0000FDFF03000000FAFF030002000000FDFFFFFF07000400FCFF01000000FFFFFDFF0300FDFFFEFFFDFF010000000000FCFF0400030000000200FFFF0300FFFF0100FFFFFEFFFEFFF9FF020000000200FFFF01000000FEFFFDFFFFFFFDFFF9FF0200FDFF02000300FDFFFDFFFEFFFFFF040000000000000000000100FEFF01000100000000000100FFFF00000000FDFFFFFF0200FAFF030000000000FDFF000001000000000003000300FEFFFBFF0100FEFF0000FEFF03000000030001000900FFFF0000F9FFFCFFFFFFFBFF0300FDFFFEFFFFFF01000700FDFF0100FFFF0300FDFFFCFF0000FDFFFEFFFCFF0000FFFF03000000FCFF00000000FFFFFEFF000001000000FEFF0200000000000300FFFF02000300FFFFFCFFFEFFFAFFFDFF0200FCFFFFFF02000200FDFF030000000400FFFF020004000300020000000200FFFF02000200050000000200FDFF0300FDFF040002000000FDFFFEFF0000FDFFFFFFFFFF030002000000FCFF01000100FCFF02000000030002000000FFFF0800FAFF02000000FCFF03000000FEFF04000200FCFFFBFF00000400FFFF03000300FFFF0300010003000000020000000400010004000200020001000200020003000200FFFFFFFF04000400000000000000FFFF010002000300FEFFFEFF0000FDFF0600FFFFFFFFFDFF010007000000FFFF00000100FFFF01000000FDFF0100000002000200FCFFFFFFFEFFFFFF00000000FFFF0000FFFF02000000010000000000FBFFFBFF01000300FBFFFDFFFDFF0400FFFFFEFFFFFF0100FFFFFCFF0300FFFF0200FBFFFCFF000004000200FAFF0100FBFFFFFF03000300020000000100FBFF0100FFFF0300FFFFFFFFFEFF0100030000000000FDFF020000000200FCFF060000000000FFFF0500FAFF0200FCFFFFFFFCFFFEFF0100FDFFFFFFFDFF0000FDFF01000100FCFF000001000200010004000200F9FF020001000100FFFF0000FFFFFEFFFDFF0100FFFF0000FEFF0500FFFF0300030008000300FBFFFFFFF9FFFFFF0400FCFF07000400FAFF0000FFFF010002000200080003000000FFFF030000000300FBFFFFFFFCFF02000100FBFFFFFF0900FCFF0000FDFF020004000400FBFF0300FEFFFFFF0400FCFFFFFFFBFFFCFF0000FEFFFEFFFFFF0200FFFFFEFFFFFF04000100FFFF01000300FEFF010001000100FCFF02000200FFFF0300FDFFFBFFFEFF0700FDFF01000200050000000900FFFFFCFFFBFF020003000100FDFFFFFF0100F8FF0300FEFF020001000000FCFFFCFF0400F7FFF9FF0300FFFF01000100FFFFF9FF050004000000FFFF0300FDFF0200FFFF030000000300FEFF0100FFFF010004000300FDFF0300FCFF0300000003000000030002000100FCFF0000000002000200FDFF0300FEFFFEFF000000000400FFFFFEFFFCFF0200FBFF03000100010000000000030000000400FEFFFCFF02000500FDFF02000000FEFF0500FDFF0100FFFF02000200000007000100FFFF000000000000FCFF03000000FDFFFEFF03000100FFFFFEFFFEFFFEFF08000000FFFF0400FEFFFFFFFEFF04000000FAFFFEFF000006000200FCFF0000FDFFFBFFFCFF0100FCFFFEFF0600FEFFFFFFFFFF03000200FCFF0400FFFFFFFF000003000400FFFF0100FDFFFFFF0200FCFF0200FFFF0100FEFFFCFFFFFF0200FCFFFAFF02000000FCFFFFFFFFFFFDFFFFFF020001000500000004000600FFFFFFFF00000200050001000100FFFF02000800FFFF010002000300FFFF0100FBFFFBFFFCFF0100FEFFFEFFFEFF0000F8FF0100FEFF0100000004000000FDFFFFFF0000FFFF02000200FFFF020001000200050003000000030001000100FEFFFFFF0300FEFF0400FDFFFFFF0000FFFF0100FDFF0000FFFF0100FFFF04000200FFFFFBFFFCFF0000FDFFFFFFFBFF0100FFFFFFFF000000000100FCFFFCFF010000000200FDFF060001000500FEFF01000400030000000000FDFFFFFF04000100FFFFFFFFFEFF03000100FEFFFDFF0400020000000200FDFFFDFF02000000000003000100FCFF0000FDFFFFFF0000FEFFFEFF0000FAFF0200000002000100000006000100FFFF05000100FEFFFCFFFAFF020001000000FEFFFFFFFBFF0700FEFF03000000FFFF04000000FDFF0100050000000000FFFF0100FDFFFEFF0000000005000200000002000400FFFFFEFFFEFFFFFFFFFFFFFF01000200FCFFFEFF040000000200060001000100FBFF000002000300FFFF02000100FFFF02000200FCFF01000000FFFFFBFF0200FBFFFEFFFEFFFCFF00000400FDFFFDFF00000300040001000400FDFFFAFF03000400FEFFFEFFFCFFFEFFFEFF0100FCFFF8FFFEFFFFFF00000400030002000200FEFFFDFFFCFFFFFF0100020004000000FCFF0200FAFF0400FDFF000003000200FCFF0100020003000100FEFF0100000004000100FFFFFDFF0000010000000500FFFF0000FEFFFCFF0400FEFFFEFFFDFFFDFF02000600000004000400010002000300010001000000FEFFFFFFFFFFFDFF0200FEFF02000000FBFF0500FEFF03000300FFFF01000200FFFFFEFFFEFFFEFF01000600020001000100FEFF0000FCFFFFFFFCFF02000300FEFF0000FEFFFCFFFDFFFCFF00000300010002000100FDFF0000FAFF00000000FCFF040003000000F9FFFEFF03000400FFFFFCFF0100020005000200060000000400020006000000FCFF000004000100FEFFFFFF0100050001000200FEFF0700FCFFFFFFFEFFFDFF00000200FBFFFFFFFCFF03000000FCFFFEFF0000030004000000FEFF0100FDFF020001000100FEFFFEFF00000500FEFFFFFF0200FFFF0300FDFFFEFF00000000FEFF01000000FDFFFCFFFFFFFFFF0300FEFF0200FDFF0200FEFFFCFF0500030000000400FEFFFEFFFBFF0000FDFFFFFFFFFF0200FBFF0200FEFF0000000003000100FCFF010006000000FFFF0300010003000100FCFF0000FEFF0200FEFF03000200FDFFFFFFFEFFFEFFF9FFFDFF0800FBFF02000000FEFFFCFF010000000200FFFFFBFF00000100FEFFFFFFFFFF05000000FCFF0300FAFF0300FAFFFDFFFDFF0400FDFFFDFFFDFFFBFFFEFFFDFFFFFFFEFFFFFFFCFF010001000000FCFF00000000FBFFFFFFFDFF0100FAFF02000400FBFF050005000100FEFFFEFF01000100FEFF000002000100FAFF0200FDFFFFFF00000100FBFF01000200FDFF0000FEFFFEFF040003000100000001000000FDFF00000200FEFF0000030002000200FFFF01000000000000000000FDFF01000100FDFF02000100040000000100FEFF050002000300FEFFFEFFFFFF0000FDFF0300FDFF02000200FEFF02000100FFFF0600FDFFFBFF0000FEFFFEFF00000500000004000300FDFF0500FEFF0100030002000000FFFF0000010000000200FDFF030000000500040003000200FEFFFFFF00000100FFFF0100FDFF0200FDFFFFFF0300FAFF0300FFFFFEFF0100FEFFF8FF0500FCFFFDFF02000300FFFF040005000100020002000200FEFF00000000FEFFFDFFFEFFFEFF0100FEFF01000300FEFFFCFFFBFFFEFFFFFF0100FEFF030002000200F9FFFEFFFEFF03000100FFFF0100FEFFFEFF000003000000020001000300FFFF0200FCFF0100FCFFFFFFFCFF0100020000000100FDFF06000200010000000100FEFFFEFF0100FFFFFEFF0800FBFFFEFFFEFFF9FFFEFF0500FFFF0000FEFF02000100FFFFFDFF0100FEFF000000000300FAFF0300FDFF0100FDFFFEFF0200FCFF0300FDFF0200020000000300FAFF01000000060002000000FEFF00000400FEFFFFFFFEFFFBFFFDFF00000000FEFF04000200FEFF0700020005000200FFFFFEFF0100FEFF0000FDFFFEFF0000FCFFFDFF07000000FCFFFFFF0600FEFFFCFFFDFF00000100050000000000FBFF00000300FCFF0100FEFFFFFFFEFF0000FBFF0000000004000200FBFF0000FCFF0100FBFF01000100FAFFFDFFFFFF02000400FCFF00000000FEFFFAFFFDFFFFFFFAFF0000FCFFFEFFFEFF0000000001000500FAFF0100FDFF02000300FEFF0500FFFF04000100FDFFFCFFFEFF0500FCFF090004000000FDFF0200FEFFFFFF00000100FAFF0100FBFF0300FEFF01000400010004000000FCFFFCFFFFFF00000100FFFFFCFF0100FDFF01000000FDFFFCFFFEFF00000100050000000100FCFF0300FFFF0100FEFF0400040001000200FDFF03000200FFFF0400FFFFFEFFFAFFFBFF05000400FFFFFAFF0000030001000000FFFFFFFFFFFF0400F8FF03000000FDFF0100FFFF02000200FEFF0100FFFF0200FDFF05000100FDFFFFFFFDFFFFFF02000200010000000000FDFF01000400FEFF02000000000003000200FDFFFDFF0500010002000100FCFFFDFFFEFF0000FFFF01000100FFFF060001000000FFFFFFFFFEFFFFFFFDFF0400FCFF0100FFFFFFFF0100010002000300FFFFFFFF0300FCFF00000200FEFFFEFFFEFF0200FDFF010003000600010001000500000002000400FDFF02000600FFFFFEFF0500FDFF02000300FFFFFDFFFEFF0400FDFFFFFFFEFF0200FBFF0000020003000000FEFF0700FEFFFDFF0900FFFFFEFFFDFFFFFF000002000500FEFFFCFFFDFFFFFFFFFF0100FFFF0100FFFFFDFF000003000000FBFF00000500020003000100FEFF00000400FFFFFDFF0200FDFF01000000FDFF020000000200FBFFFEFF0200FFFFFAFF0000FEFF0300FDFFFDFFFDFF0500FDFFFFFF000002000200FBFF0100FFFF01000600FDFFFFFF01000400FCFF0000000005000000020001000300000003000100FAFF020002000000FFFFFFFF0000FEFFFFFFFFFFFFFF0300FFFFFFFF000000000500FFFFFFFF00000400FFFF0000FDFFFFFFFCFF0100FDFF040004000000FCFF02000700FDFF06000100FEFFFEFF0200010002000000FEFFFFFFFEFFFEFFFCFFFEFFFFFFFEFFFCFF05000000FBFFFFFF0200FEFF030000000000FDFFFEFF0000FEFF02000300FDFFFFFF0500060001000200010000000000FEFF0000FCFF02000300FFFFFEFFFDFFFEFF03000500FDFF00000200FDFF0200FDFFFFFF0500000002000500FFFF01000000FEFF04000000FFFF0200020004000000010005000200FCFF00000600FFFFFFFF0100040003000100FFFF0400FFFF000001000100000001000300000005000400FEFF0100FEFF02000800FFFF0000040000000300020001000200040003000200FFFFFFFFFFFF0300FFFF0300FBFF0100FEFF0100FFFF0200FFFF0100FEFFFDFF0200FBFFFFFF05000400FDFF01000100FEFF000001000100FFFFFEFF010001000000FEFFF9FFFEFF0000FFFF0200FFFFFEFF0200FFFF0300FDFF0400FDFF0200020007000400FEFF010005000100FBFF01000000020005000300FFFF0400FCFF0400000003000000FBFF01000400FFFF0000FFFF04000500FCFFFEFF0000FDFF01000600FAFF0300FFFF000000000000FFFF01000100FDFF01000200040003000100050001000100FCFF0400FFFFFDFFFEFFFDFFFCFF02000200000000000400FEFFFFFFFEFFFAFFFCFF0100FBFF01000000FEFF0400FDFF08000100FFFF01000700FEFF02000400FDFF0700FEFFFFFF00000200FDFFFFFF010002000200FFFF06000100F9FFFCFFFCFFFEFF060000000300FBFF03000200FEFFFFFF030000000600FCFF0200000002000200FFFF0200FFFFFFFFFFFF0300FDFFFCFFFFFFFFFFFAFFF9FFFCFF0200020000000300020002000000020001000500000003000000FDFFFEFFFEFF0000050002000000010005000000FEFF010003000300FBFF0300000003000000FBFF00000400FEFF04000100FBFF000003000000FCFF000002000200FDFF06000400FFFF0300FFFFFFFF00000300010003000200FEFFFFFFFFFFFEFF010000000400FEFF0200FEFFFFFF010002000000000001000400FEFF0300000002000400FFFF0000FFFF05000200FCFF0300FFFF02000200FCFF0400FEFFFEFF0100FEFF0200FDFF0100FFFFFAFFFAFF0300FCFF00000100010000000000FFFFFDFF030003000000FBFFFFFF010002000000FBFFFFFFFEFF0000FFFFFFFF03000000FFFFFEFF030000000200FEFFFFFFFDFFFFFF0600FFFF000003000100FEFF0100FFFF02000300FEFFFFFFFDFFFBFF0200FEFF020001000200000001000200FFFF03000300030001000200FDFFFDFFFEFFFBFFFBFF03000600020002000400FFFF010001000600000004000100FEFFFCFF0400FEFFFFFF000001000400000005000100FDFFFFFF00000100FEFF0000FEFFFEFF00000400FDFFFFFF0000FFFF04000100FCFFFEFFFEFFFEFFFEFF00000000030002000000FEFFFBFFFFFF0700FCFFFDFFFCFF03000300FDFFF8FFFFFFFFFF0300FCFF0100FFFFFFFF04000200FEFFFBFF0400FCFFFEFFFCFFFFFF00000500FDFF01000000FCFFFEFF0200FFFF0200FFFF040002000100FFFFFDFFFFFFFCFF0200FDFFFEFFFCFFFBFFFDFFFDFF020002000200FFFFFEFF070001000100FFFFFFFF0700FAFF0000FEFF0200FFFF0400FDFF03000200FEFF00000000FEFF0200FBFFFEFFFEFF02000100FCFFFFFFFFFF00000000FFFFFFFF0000FBFF0300010002000000FCFF00000200FCFF0400FEFFFFFF0100FDFFFEFFFCFF0400FDFF01000100FDFFFAFF00000100010000000000000001000200050003000300FFFF0100FCFF0100FDFF010001000600FFFF0000FEFF070001000100FFFF040000000000FCFFFCFFFFFFFEFFFEFFFBFFF6FF00000100FEFFFEFF0300FFFF0300FAFFFEFF0100FFFFFFFF01000000FFFFFFFFFFFFFEFF0200F9FFFEFFFEFFFEFFFCFFFFFF000002000100FCFFFFFF0400FFFF02000500FEFFFDFF030000000100FEFF020002000500FFFF00000400FEFF000004000200010000000300FDFFFDFF0000FEFF01000200FEFF0100FEFF0000020003000300040000000300FEFF04000200FFFF04000100FDFF02000100FFFF0300FDFFFFFF03000300020000000300FDFFFFFFFFFF03000200FDFF0200FFFF0200F9FFFEFFFDFF02000400010002000200F9FFFDFFFDFFFAFF04000200FDFF0000FFFFFFFF0000FBFF0400FCFF0200FCFF0400FDFF0400050001000000FFFFFDFF05000700FCFF00000200FEFF050004000300000003000200FCFF0000F9FF0200020004000100010003000200040001000100FEFFFCFFFFFFFFFF000002000500FDFFFDFF0000000002000000FEFF0400000000000100FDFFFBFFFCFFFFFF0100FFFF0000FEFFFBFF02000000FEFF0000FDFF010003000200FDFFFFFF0100010001000200FFFF0000FDFF00000100FFFF0400FFFFFDFF0000FDFFFEFF02000000050001000300FFFFFDFF00000500030002000400050001000200FEFF000002000200FEFFFFFFFDFF02000200060000000100FEFF0200FBFFFFFFFFFF010003000100FCFF070002000000FFFF010001000100FBFF03000100FEFFFFFFFFFF0300FEFF0200FFFF06000000000003000100FFFF010000000200FFFFFBFF0100FEFF0000FDFFFCFF04000100FDFF04000400000002000000FDFF0400000001000500FFFF0100000005000200FBFF00000000FDFFFDFFFDFF0400FFFFFEFF0100F9FFFFFF02000700FDFF00000000FCFFFEFF0000FDFF03000100FEFFFEFFFEFFFCFF0400000000000100020000000700FFFFFEFF0000FCFF0200FDFF0000FFFFFAFFFFFF0300FEFF01000400FFFFFDFFFCFFFFFF04000900FFFF02000000FFFF01000000030003000200FDFFFFFF05000100010000000100FFFFFCFF010001000100FEFFFBFF0400040002000100FFFFFEFF02000200FBFFFDFF01000500FAFF0000FEFF010004000400FDFF04000100FEFF0100FBFFFAFF0200FFFF020000000400FFFF010001000100010004000100FDFF0100FEFF0300FDFF0000FFFFFFFFFEFFFFFFFEFF0100FEFFFBFFFEFFFDFF0200FDFF020002000100030004000100FEFFFFFFFEFFFFFF00000000FEFFFCFFFDFF0000FFFFFEFF0200FDFF06000000000004000600030000000100FEFFFEFF000000000100040000000600FDFFFEFF0000FFFFFEFF04000000F8FF00000200FDFF0100020008000100FBFF020005000300050005000100FBFF00000100FFFF0100FEFFFEFF00000300FFFFFFFF00000500FFFFFFFF0000FBFFFBFF0200FFFF070000000300FCFFFDFF0400FEFFFFFFFDFF01000200FDFF010003000100FCFF0400FFFF0100FDFFFCFFFCFF0400FDFF0000FDFFFFFFFEFFFEFF07000400FEFF030006000500FDFF0300FEFF01000100FCFF020001000000FEFF0200F9FF01000000FDFF000003000200FDFF0200FAFF06000100FDFFFFFFFFFF0100FBFFFEFF0000FDFF0600FCFF0100FFFF0000FEFF02000300FFFF0100FAFF020001000400FFFFFCFF03000100FFFF0200010004000300FEFF0300FAFF0300FFFF0400020003000200FEFF0100FEFF0000FDFFFEFF0000000001000300FDFF000003000500FEFFFDFF0000FEFFFEFFFCFF00000200FFFF03000200FFFFFEFF020004000000FEFF0300FFFFFEFF01000100FEFFFEFFFFFFFDFF0000FEFF0000020000000700FEFF0100FEFF01000200010001000100FDFFFFFFFEFF02000200FEFF030004000400020000000000FDFF0000FFFF0100FFFF0200FFFFFDFFFFFFFDFFFEFF0300FFFFFFFF0200FFFF01000300FFFFFCFFFCFF050003000100FCFFFFFF0000FEFF00000100FCFF0000FEFF00000000FDFF0300000000000100010001000100FDFF0000FDFF0000050000000800FCFF0500FCFF0100FBFF0200FFFF0200000001000500040002000200F9FF010006000000FDFF0000FDFF0400030001000400FAFFFDFF0200FFFFFBFFFDFFFFFFFFFF0700FEFF0000FEFFFFFFFDFF0100FEFF020000000700FEFF0300FEFF02000000010005000000FFFF03000300FEFFFFFF0200FEFFFFFF010000000100FFFFFFFFFEFF00000100060000000000FFFF0500FEFF0100FFFFFFFF0200FAFF050002000100FEFF0000FEFF0200FFFF000000000200F9FFFBFF040001000200020002000200FEFF05000300FFFFFDFFFBFFFDFFFBFFFEFF0200FFFF03000300FCFFFFFF0600FCFF02000400FEFF02000100030002000200FFFFFCFFFAFFFDFFFDFFFDFF0200FBFFFEFF05000100FFFFFEFF02000200FEFF00000200FEFF0000FBFF08000200FCFFFCFFFCFF00000200060001000200F8FF0100FEFF0100FDFF010003000100000003000000FFFF0300FEFF0500FFFF04000100FEFF02000100FEFF03000000FEFFFDFF0000FBFF0100FEFFFFFFFBFF030001000000040001000200FBFF0100FEFF05000300FDFFFCFF0300FEFF0300FEFF0000FFFFFAFF0300FFFF02000200FEFF0300FEFF0200FCFF00000200FFFFFFFF0200010003000400FFFF02000300060000000000FEFFFDFF0200FEFFFFFF0100FFFF0200FFFFFDFFFFFF04000100000003000200FFFF0000FFFF0000FDFF020001000100F9FF00000000FEFF00000200FFFFFDFF0000050000000300FEFFFFFF0500000003000000FFFFFFFFFFFFFCFFFEFF0200FFFFFFFF0000FEFFFCFF02000300FDFFFFFF02000100FEFF0300F8FF0900FCFFFEFFFCFFFEFFFFFFFDFF03000400FCFFFFFF02000300010007000200FFFFFEFFFEFFFBFF0300FEFFFBFFFDFF0100060003000000FDFFF6FFF8FFFDFFFFFFF9FF0600FFFFFFFF0300FEFF0200FDFF010002000000FFFF0000040001000000010004000100FDFF0700FFFFFBFF00000300FDFF010003000300FFFF08000200FEFF0100FFFF0200FDFFFCFF0200FDFFFFFF0100FFFFFEFFFEFFFFFF030000000300000003000200FEFF0300FEFFFFFF03000400FFFFFCFF010001000100FFFF05000000FDFFFAFFFEFFFDFFFEFF0000FDFFFFFF0300FDFFFFFFFEFF03000300FCFFFFFFFEFF0600FEFFFCFF070001000400FCFFFEFFFEFF00000900F9FF0000FFFF0100040002000100FCFFFFFF0200FDFF050001000200FFFF020001000100FEFF0400FBFFFDFFF9FF0200FEFFFFFF0100FDFF060003000600FDFFFFFF0200FCFFFFFFFCFFFEFF000001000500FBFF0100020000000300F9FF000001000100FFFF03000000FCFFFFFF05000000FAFF0100FFFF0100010001000000FEFF0000000002000000FFFFFFFF030003000000FEFFFFFF00000300FEFF0300FDFF010000000000FFFFFEFF040004000500030003000300010000000300FEFFFDFF03000100FEFFFEFF01000000FFFFFCFFFDFF01000200FEFFFEFFFCFFFCFFFEFF0000FBFFFFFF01000500F8FF0100FEFF00000300FCFF0200FFFFF5FF020001000100010000000200FCFF0200FEFF0200FEFF0300FEFF03000500FFFFFBFFF9FF0000010007000400FFFF0300FFFF0200FDFFFBFF0200FEFFFFFF060001000300FCFFFFFFFBFF0200FEFFFFFFFCFF010005000100FFFF0300FFFFFEFFFEFFFFFF0200020000000500FEFFFFFFF9FF0300FFFFFAFF0000FBFFFFFF0000FCFF04000000FFFFFEFFFEFFFEFF0200FCFF000002000000FFFF020001000100FDFF000001000200FFFF0300FDFFFEFFFFFFFDFF0100000004000300FFFF030000000100FDFF0100FFFFFEFFFEFF00000000FCFF00000100FBFFFEFF000004000400FEFF02000100FEFFFEFFFEFF01000400000000000000FFFFFCFF050001000500FFFFFDFFFEFF0000FEFFFDFF0000FDFF000005000300010000000200070002000000FDFF050004000700FAFF0000FEFF0400FEFFFDFF000002000000010000000400010003000200FFFF0000FFFF0100FEFFFEFF0200FFFF00000000040001000300FEFF0000FCFFFFFFFCFF0200000003000300FBFF0200FDFFFDFF0100030005000400020005000200010002000200030002000100FFFFFBFF0000FDFFFBFFFCFF0200FFFF0300FEFFFFFFFBFF0000FEFF05000800FFFF000000000100040004000400010000000000030000000500FDFF030000000200FEFF00000100FEFFFFFF00000200040000000100FCFF020000000300020001000400FEFFFDFF0000FCFFFFFFFDFF0300030001000000010000000000020003000100FBFFFFFFFEFF0300FFFF03000200FEFF0400010000000200FDFFFFFF0200020003000000FEFF01000000FCFF0200010000000200FDFF01000200FFFFFBFF050003000100000001000700FEFFFFFFFEFFFEFFFEFF0100030001000500FFFFFEFF0100FDFFFDFF0300FDFF0500000001000000FEFF0200FFFF0000FEFFFBFFFEFF0400FFFFFEFF0000FAFFFEFF030000000100040004000000030005000000FFFF0000FFFFFDFF0100FEFFFDFF0000FDFF000000000000FEFF0300FFFFFFFFFCFF02000400FEFF01000400FEFF03000100FFFFFDFF0100FDFFFDFFFBFFFFFFFFFF020004000100FBFFFEFF030000000000FAFF0100000002000100FBFF0500FDFFFCFFFEFF0000010002000400020000000600FDFFFFFFFEFFFDFFFCFF0400FEFFFEFFFEFF0200FFFF040001000400FCFFFFFFFFFF0000FBFF030003000200FBFF0600FEFF030005000000FDFFFFFF04000200040002000100060002000000000003000100FCFFFFFFFEFF0300090003000200FBFFFDFF040007000200FCFF0100FDFF04000100FFFFFFFF04000200FBFFFEFF0600FEFF0400FEFFFDFFFDFF0100FFFFFFFF030002000200F8FF0000FEFF0000030002000000FBFF0200FEFFFEFFFBFF02000200FCFF01000300FFFF0000050002000100FDFF0100FBFF0200FEFFFFFFFEFFFDFFFBFF0100010000000200000001000000FFFF01000000FFFFF9FFFDFF02000200FDFF03000000F8FF03000400FCFF050001000300FAFF0200FFFFFEFFFDFFFDFFFDFF0200FDFF020001000100FEFF0200FFFF0000FBFF0500FEFF0000FEFFFEFFFEFF0100020001000100FEFF0000FEFF0400FDFFFFFF0400FBFF0300030002000300FBFFFDFFFEFFFFFFFFFF0100FFFFFEFFFCFF010001000200FEFF0200020001000000FCFF0300FCFFFCFFFAFFFFFF000004000000000002000100FFFFFCFF010001000600FDFFFFFF00000100FEFF03000300FCFF01000200FEFFFBFFFEFFFBFF0500010005000000030000000000FFFFFEFFFCFF03000100FFFFFDFFFDFF01000000050004000300FCFFFEFFFFFFFBFFFFFFFDFF06000400010004000000FEFFFFFFFEFF0100FDFF060000000300010001000100FDFF0000F9FF00000200FAFF00000100FCFFFEFF02000000FEFF00000100FDFF000001000000FFFFFFFF02000500040001000200FFFFF9FF0400FEFFFFFF05000000FBFFFFFFFCFFFFFF00000200FEFF0000FEFFFEFFFDFF0200FDFF0100FCFFFDFF0000FFFF020000000100FEFFFFFFFCFFFEFF02000100FAFFFFFF020000000000FDFF0000FEFFFBFF000004000300000002000000FEFF0000FDFF00000000040002000200FDFFFEFFFEFF01000400FCFF01000000FDFF0300FFFFFEFF04000100FEFFFEFFFFFF0100FBFFFFFF0100000000000000000002000100FCFFFCFF0200FFFFFFFFFEFFFFFF0100FCFF0000FFFFFFFFFEFF0300FFFFFDFF01000800FDFFFAFF01000000020001000000FEFFFFFFFFFF0200FCFFFCFF0000FEFFFDFF0100FEFF0400FFFFFCFFFFFFFEFF00000100FDFF0200FFFF00000600010004000200FEFF520D3A4E89237A435B3AC5166E1A2E05"
    server.call_third_interface(UID, rec_secret_key)

if __name__ == "__main__":
    main()