import pickle
import os
import numpy as np
import concurrent.futures
import multiprocessing
import time
import logging
import argparse
from typing import Tuple, Optional, List, Dict, Any
from frodokem import FrodoKEM
from fpylll import IntegerMatrix, LLL, BKZ # Removed FP_NR
import bitstring

# # Attempt to import fpylll, provide guidance if missing
# try:
#     from fpylll import IntegerMatrix, LLL, BKZ, FP_NR # FP_NR for floating point type
#     FPYLLL_AVAILABLE = True
# except ImportError:
#     FPYLLL_AVAILABLE = False
#     # Define dummy classes if fpylll not found, so script can load/parse args
#     class IntegerMatrix: pass
#     class LLL: pass
#     class BKZ: Param=None; DEFAULT_STRATEGY=None; reduction=None
#     FP_NR = None

# # Assuming frodokem.py is in the same directory or PYTHONPATH
# try:
#     from frodokem import FrodoKEM
#     FRODOKEM_AVAILABLE = True
# except ImportError:
#     FRODOKEM_AVAILABLE = False
#     # Dummy class if frodokem not found
#     class FrodoKEM: pass

# Setup basic logging for feedback
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger("Solver")

# --- Constants & Configuration ---
# Placeholder - needs verification based on analysis of the rounding behavior
# Example: If boundary crossing at delta_thresh means -S_kl = delta_thresh mod M
# then S_kl = -delta_thresh mod M
def delta_thresh_to_S_known(delta_thresh: int, modulus: int) -> int:
    """
    Converts the observed delta_threshold to S[k][l].
    Reverting to the original approach: (delta - M/2) mod M, then centered.
    """
    if delta_thresh is None:
      log.warning("Encountered None for delta_thresh, returning 0")
      return 0
      
    modulus_half = modulus // 2  # 4096 for Frodo-640

    # The minimal positive delta causing a rounding change is
    #   delta_thresh = (M/2 - (S[k][l]  mod  M))  mod  M
    # hence we invert this relation to obtain an estimate of S[k][l].
    # We work modulo M and then centre the result into the signed range.

    # Recover S[k][l] modulo M (inverse of threshold relation):
    #   delta_thresh ≡ (M/2 - S) mod M  =>  S ≡ (delta_thresh - M/2) mod M (up to sign)
    # Empirically from attack traces, the direct relation is S ≡ (delta_thresh - M/2) mod M
    s_kl_mod_M = (delta_thresh - modulus_half) % modulus

    # Centre into the interval [-M/2, M/2)
    if s_kl_mod_M >= modulus_half:
        s_kl_centered = s_kl_mod_M - modulus
    else:
        s_kl_centered = s_kl_mod_M

    log.debug(
        f"Converting delta_thresh={delta_thresh} -> S_known={s_kl_centered} (mod {modulus}); "
        f"intermediate s_mod={s_kl_mod_M}"
    )

    assert -modulus_half <= s_kl_centered < modulus_half, (
        f"Centering failed (delta={delta_thresh}, s_mod={s_kl_mod_M}, modulus={modulus})"
    )

    return s_kl_centered

# --- Data Loading ---
def load_solver_data(uid: str) -> Optional[Dict[str, Any]]:
    """Loads the solver input data from the pickle file."""
    input_dir = "solver_inputs"
    input_filename = os.path.join(input_dir, f"solver_inputs_{uid}.pkl")
    log.info(f"Attempting to load solver data from: {input_filename}")
    if not os.path.exists(input_filename):
        log.error(f"Input file not found: {input_filename}")
        log.error("Please ensure 'attack_solver.py' was run successfully first.")
        return None
    try:
        with open(input_filename, 'rb') as f:
            solver_data = pickle.load(f)
        log.info(f"Successfully loaded data for UID: {solver_data.get('uid')}")
        # Validate essential keys
        required_keys = ['uid', 'variant', 'seedA', 'B_matrix', 'approximations']
        if not all(key in solver_data for key in required_keys):
            log.error("Loaded data is missing required keys.")
            return None
            
        # Check for optional S_true
        if 'S_true' not in solver_data:
            log.warning("True S matrix ('S_true') not found in input file. Cannot perform comparison.")
        elif solver_data['S_true'] is None: # Handle case where S_true read failed in attack_solver
            log.warning("True S matrix ('S_true') is None in input file. Cannot perform comparison.")

        return solver_data
    except pickle.UnpicklingError as e:
        log.error(f"Error unpickling data from {input_filename}: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error loading {input_filename}: {e}")
        return None

# --- Matrix Preparation ---
def prepare_matrices(solver_data: Dict[str, Any]) -> Optional[Tuple[Any, np.ndarray, np.ndarray, np.ndarray, int, int, int, int]]:
    """Generates matrix A, converts B, and prepares S_known."""
    # if not FRODOKEM_AVAILABLE:
    #     log.error("FrodoKEM library not found. Cannot generate Matrix A.")
    #     return None

    log.info("Initializing KEM to generate Matrix A...")
    try:
        kem = FrodoKEM(solver_data['variant'])
        q = kem.q
        n = kem.n
        nbar = kem.nbar
        modulus_approx = kem.q // (2**kem.B) # Should be 8192
        assert q > 0 and n > 0 and nbar > 0 and modulus_approx > 0, "Invalid KEM parameters"
        log.info(f"KEM Params: q={q}, n={n}, nbar={nbar}, Mod_Approx={modulus_approx}")
    except Exception as e:
        log.error(f"Failed to initialize FrodoKEM with variant {solver_data['variant']}: {e}")
        return None

    log.info("Generating matrix A (this might take a moment)...")
    try:
        A_matrix_list = kem.gen(solver_data['seedA'])
        A_np = np.array(A_matrix_list, dtype=np.int64) % q
        log.info(f"Matrix A generated ({A_np.shape})")
        assert A_np.shape == (n, n), "Matrix A has incorrect dimensions"
    except Exception as e:
        log.error(f"Failed to generate Matrix A from seedA: {e}")
        return None

    # Convert B_matrix (list of lists) to NumPy array
    try:
        B_np = np.array(solver_data['B_matrix'], dtype=np.int64) % q
        log.info(f"Matrix B loaded ({B_np.shape})")
        assert B_np.shape == (n, nbar), "Matrix B has incorrect dimensions"
    except Exception as e:
        log.error(f"Failed to convert B_matrix to NumPy array: {e}")
        return None

    # Convert approximations list to S_known matrix
    try:
        log.info("Constructing S_known matrix from approximations...")
        S_known_matrix = np.zeros((n, nbar), dtype=np.int64)
        approximations = solver_data['approximations']
        num_approximations = len(approximations)
        expected_approximations = n * nbar
        if num_approximations != expected_approximations:
             log.warning(f"Warning: Number of approximations ({num_approximations}) does not match expected ({expected_approximations}).")

        processed_count = 0
        missing_count = 0
        for k, l, delta_thresh in approximations:
            if 0 <= k < n and 0 <= l < nbar:
                 if delta_thresh is None:
                      log.warning(f"Missing approximation for S[{k}][{l}]. Using 0.")
                      S_known_matrix[k, l] = 0
                      missing_count += 1
                 else:
                      # Apply the corrected conversion
                      S_known_matrix[k, l] = delta_thresh_to_S_known(delta_thresh, modulus_approx)
                 processed_count += 1
            else:
                log.warning(f"Ignoring approximation with out-of-bounds indices: ({k}, {l})")

        log.info(f"S_known_matrix (mod {modulus_approx}) constructed. Processed: {processed_count}, Missing: {missing_count}.")

    except Exception as e:
        log.error(f"Failed to construct S_known matrix: {e}")
        return None

    # --- [NEW] Verify S_known against S_true (if available) --- 
    S_true_matrix = solver_data.get('S_true')
    if S_true_matrix is not None:
        log.info("Comparing constructed S_known with loaded S_true...")
        try:
            S_true_np = np.array(S_true_matrix, dtype=np.int64)
            if S_true_np.shape == (n, nbar):
                mismatches = 0
                modulus_half = modulus_approx // 2
                first_mismatch_info = ""

                for k in range(n):
                    for l in range(nbar):
                        s_true_val = S_true_np[k, l]
                        s_true_mod_M = s_true_val % modulus_approx
                        s_true_centered = s_true_mod_M
                        if s_true_centered >= modulus_half:
                             s_true_centered -= modulus_approx
                        s_known_val = S_known_matrix[k, l]
                        if s_known_val != s_true_centered:
                            mismatches += 1
                            if mismatches == 1:
                                 first_mismatch_info = f" First mismatch at S[{k}][{l}]: S_known={s_known_val}, S_true={s_true_val} (centered mod {modulus_approx} -> {s_true_centered})"
            
                if mismatches == 0:
                    log.info(f"  SUCCESS: S_known matches S_true (centered mod {modulus_approx}) for all {n*nbar} entries!")
                else:
                    log.warning(f"  FAILURE: Found {mismatches} mismatches between S_known and centered S_true (mod {modulus_approx}).{first_mismatch_info}")
                    if mismatches > (n * nbar * 0.1): # Fail if > 10% mismatch
                         log.error("  High mismatch rate (>10%), aborting.")
                         raise ValueError(f"High mismatch rate ({mismatches}/{n*nbar}) between S_known and S_true.")
            else:
                log.warning("S_true matrix loaded but has unexpected shape {S_true_np.shape}. Cannot perform comparison.")
                # Optionally raise error if comparison is mandatory
                # raise ValueError("S_true matrix has incorrect shape.")
        except Exception as comp_ex:
            log.error(f"Error during S_known/S_true comparison: {comp_ex}")
            raise comp_ex # Re-raise exception to halt execution
    else:
        log.warning("S_true not found in solver data. Cannot verify S_known accuracy.")
    # --- End Verification --- 

    return kem, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx

# --- Lattice Solver Worker ---
def solve_column_worker(args: Tuple[int, np.ndarray, np.ndarray, np.ndarray, int, int, int, int, int, str]) -> Tuple[int, Optional[np.ndarray]]:
    """Solves for one column s_j_unknown using lattice reduction."""
    col_j, A_np, B_np, S_known_matrix_np, q, n, nbar, modulus_approx, bkz_block_size, bkz_float_type = args
    worker_log_prefix = f"[Worker {col_j}]"
    log.info(f"{worker_log_prefix} Starting...")
    
    # --- Assertions on Input Data --- 
    try:
        assert A_np.shape == (n, n), f"Worker {col_j}: Incorrect A shape {A_np.shape}, expected ({n},{n})"
        assert B_np.shape == (n, nbar), f"Worker {col_j}: Incorrect B shape {B_np.shape}, expected ({n},{nbar})"
        assert S_known_matrix_np.shape == (n, nbar), f"Worker {col_j}: Incorrect S_known shape {S_known_matrix_np.shape}, expected ({n},{nbar})"
        log.debug(f"{worker_log_prefix} Input matrix dimensions verified.")
    except AssertionError as e:
        log.error(f"{worker_log_prefix} Input assertion failed: {e}")
        return col_j, None
        
    # --- Main Worker Logic --- 
    try:
        # Calculate target vector b'_j = (b_j - A * s_{j,known}) mod q
        s_j_known = S_known_matrix_np[:, col_j]
        b_j = B_np[:, col_j]
        # --- Log first few values --- 
        log.debug(f"{worker_log_prefix} s_{col_j}_known[:5]: {s_j_known[:5]}")
        log.debug(f"{worker_log_prefix} b_{col_j}[:5]: {b_j[:5]}")
        # -------------------------- 
        log.debug(f"{worker_log_prefix} Calculating A * s_j_known...")
        A_s_j_known = (A_np @ s_j_known) % q
        b_prime_j = (b_j - A_s_j_known + q) % q # Ensure positive result
        # --- Log first few values --- 
        log.debug(f"{worker_log_prefix} b'_{col_j}[:5]: {b_prime_j[:5]}")
        # -------------------------- 
        log.debug(f"{worker_log_prefix} Calculated b'_j.")

        # Restore scaling A' = (M * A) mod q
        log.debug(f"{worker_log_prefix} Calculating A' = {modulus_approx} * A % q ...") # Restore scaling log
        A_prime = (modulus_approx * A_np) % q # Restore scaling
        # log.debug(f"{worker_log_prefix} Using A' = A (NO scaling). Previous Mod_Approx was {modulus_approx}") # Comment out no-scaling log
        # A_prime = A_np # Comment out no-scaling assignment
        log.debug(f"{worker_log_prefix} Calculated A'.") # Restore log message

        # --- Construct the Lattice Basis ---
        # Standard search-LWE basis: find (s, e) st A's - b' = -e mod q
        # Dimension n+1
        basis_list = [[0] * (n + 1) for _ in range(n + 1)]
        log.info(f"{worker_log_prefix} Constructing basis matrix ({n+1}x{n+1})...")
        for r in range(n):
            for c in range(n):
                basis_list[r][c] = int(A_prime[r, c]) # Convert np int64 potentially
            basis_list[r][n] = int(b_prime_j[r])
        basis_list[n][n] = q

        M = IntegerMatrix(n + 1, n + 1)
        #M.set_matrix(basis_list) # set_matrix might not exist or work this way
        for r in range(n + 1):
             for c in range(n + 1):
                  # Use __setitem__ for IntegerMatrix
                  M[r, c] = basis_list[r][c]

        log.info(f"{worker_log_prefix} Basis matrix created.")

        # --- Perform Lattice Reduction ---
        log.info(f"{worker_log_prefix} Starting BKZ reduction (block size {bkz_block_size})...")
        start_time = time.time()
        # Use BKZ.reduction, params can be tuned# Pass float type string directly

        # Use BKZ.Param directly
        #params = LLL.Param(block_size=bkz_block_size, strategies=None, float_type=bkz_float_type, auto_abort=True)
        # Wrap reduction in a try-except block
        try:
             reduced_basis = LLL.reduction(M)#, params)
             # reduced_basis = LLL.reduction(M) # LLL for faster test
        except Exception as e_bkz:
             log.error(f"{worker_log_prefix} BKZ reduction algorithm failed: {e_bkz}")
             return col_j, None
        duration = time.time() - start_time
        log.info(f"{worker_log_prefix} BKZ reduction finished in {duration:.2f}s.")

        # --- Extract Solution ---
        # Reverted: Check ALL vectors for the expected solution form.
        log.info(f"{worker_log_prefix} Analyzing ALL {n+1} vectors of reduced basis...")
        solution_s_unknown = None
        
        # Check all n+1 vectors
        for i in range(n + 1): 
            vector_list = [int(reduced_basis[i, c]) for c in range(n + 1)]
            candidate_vector = np.array(vector_list, dtype=np.int64)
            last_coord = candidate_vector[n]
            is_zero_vec = not np.any(candidate_vector[:n]) # Check if first n coords are zero

            # Check for exact solution vector (0,...,0, +/-1) first
            if is_zero_vec and abs(last_coord) == 1:
                log.info(f"{worker_log_prefix} Found exact solution vector {i}: (0, ..., 0, {-last_coord})")
                potential_s_unknown = candidate_vector[:n] * (-last_coord) # Should be zero vector
                e_check = (A_prime @ potential_s_unknown - b_prime_j + q) % q 
                e_check_signed = np.where(e_check >= q // 2, e_check - q, e_check)
                max_abs_error = np.max(np.abs(e_check_signed))
                log.info(f"{worker_log_prefix} Exact Candidate {i} check: Max absolute error = {max_abs_error}")
                
                # Check against the q/8 threshold
                if max_abs_error < q / 8: 
                     log.info(f"{worker_log_prefix} Exact candidate vector {i} verified (threshold q/8). Solution IS s_unknown = 0.")
                     solution_s_unknown = potential_s_unknown # Store the zero vector
                     break # Found and verified the expected solution
                else:
                    log.warning(f"{worker_log_prefix} Exact candidate {i} failed verification (error >= q/8: {max_abs_error}). Treating as failure.")
            # Check other vector forms (elif abs(last_coord) == 1: ... restored)
            elif abs(last_coord) == 1:
                # Check for the standard (s, +/-1) vector
                log.info(f"{worker_log_prefix} Found candidate vector {i} with last coord {-last_coord} (non-zero s part).")
                potential_s_unknown = candidate_vector[:n] * (-last_coord)

                # Verification step
                e_check = (A_prime @ potential_s_unknown - b_prime_j + q) % q
                e_check_signed = np.where(e_check >= q // 2, e_check - q, e_check)
                max_abs_error = np.max(np.abs(e_check_signed))
                log.info(f"{worker_log_prefix} Candidate {i} check: Max absolute error = {max_abs_error}") 

                # Check against the q/8 threshold
                if max_abs_error < q / 8:
                    log.info(f"{worker_log_prefix} Candidate vector {i} verified (threshold q/8). Solution found.")
                    solution_s_unknown = potential_s_unknown
                    break # Stop searching once a valid solution is found
                else:
                    log.warning(f"{worker_log_prefix} Candidate vector {i} failed verification (error >= q/8: {max_abs_error}).")

        # After checking all vectors:
        if solution_s_unknown is None: 
             # This now means no vector with last coord +/-1 passed the q/8 check
             log.error(f"{worker_log_prefix} No suitable solution vector found after checking all {n+1} basis vectors.") 
             raise RuntimeError(f"Worker {col_j}: Failed to find solution vector passing threshold q/8.")

    except Exception as e:
        log.exception(f"{worker_log_prefix} Unexpected error in worker: {e}") # Log full traceback
        raise e

    return col_j, solution_s_unknown


# --- Main Execution ---
# add command line args to main for function call version
def main(cmdline=True, uid=None, cols=None, workers=None, bkz_block_size=80, bkz_float_type='mp', log_level="INFO", target_col=None):
    # override cmdline args if provided
    if cmdline:
        parser = argparse.ArgumentParser(description="Solve FrodoKEM LWE instance using lattice reduction.")
        parser.add_argument("uid", type=str, help="User ID for which to load solver data.")
        parser.add_argument("--cols", type=int, default=None, help="Number of columns (0 to nbar-1) to solve (default: all).")
        parser.add_argument("-w", "--workers", type=int, default=None, help="Number of parallel workers (default: number of CPU cores).")
        parser.add_argument("--bkz-block-size", type=int, default=80, help="The starting BKZ block size parameter (higher is slower but stronger). Default: 80")
        parser.add_argument("--bkz-float-type", choices=['d', 'dd', 'qd', 'mp'], default='mp', help="Floating point precision for BKZ (d=double, dd=double-double, qd=quad-double, mp=MPFR). 'mp' recommended.")
        parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level.")
        parser.add_argument("--target-col", type=int, default=None, help="Solve only for a specific column index j.")
        args = parser.parse_args()
    else:
        # Create a namespace object to mimic argparse behavior when called as a function
        args = argparse.Namespace(
            uid=uid,
            cols=cols,
            workers=workers,
            bkz_block_size=bkz_block_size, # Use passed value (default 80 if None)
            bkz_float_type=bkz_float_type,
            log_level=log_level,
            target_col=target_col
        )

    try:
        log.setLevel(getattr(logging, args.log_level.upper()))
        
        # Load Data
        solver_data = load_solver_data(args.uid)
        if not solver_data:
            raise FileNotFoundError(f"Failed to load solver data for UID {args.uid}") # Fail close

        # Prepare Matrices (will raise ValueError if S_known check fails badly)
        prep_result = prepare_matrices(solver_data)
        if not prep_result:
            # This path might be less likely now due to exceptions in prepare_matrices
            raise RuntimeError("Matrix preparation failed for an unknown reason.") 
        kem, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx = prep_result

        # The comparison logic is now inside prepare_matrices
        # --- [DEBUG] Compare S_known with S_true (if available and in single-col mode) --- 
        # Removed the old comparison block here 
        # --- End Debug Comparison --- 

        # Determine columns and workers
        num_cols_to_solve = args.cols if args.cols is not None and args.cols <= nbar else nbar
        num_workers = args.workers if args.workers is not None else (multiprocessing.cpu_count() - 1)
        single_column_mode = False
        target_column_j = -1

        if args.target_col is not None:
            if 0 <= args.target_col < nbar:
                log.info(f"--- Single Column Mode: Targeting column j={args.target_col} ---")
                single_column_mode = True
                target_column_j = args.target_col
                num_cols_to_solve = 1
                num_workers = 1
            else:
                log.error(f"Invalid target column {args.target_col}. Must be between 0 and {nbar-1}. Exiting.")
                return 1
        else:
            # Use all available columns, limit workers
            num_workers = min(num_workers, num_cols_to_solve)

        log.info(f"Attempting to solve {num_cols_to_solve} columns using {num_workers} workers.")
        log.info(f"BKZ Parameters: Block Size = {args.bkz_block_size}, Float Type = {args.bkz_float_type}")

        # --- Parallel Solving ---
        S_recovered_matrix = np.zeros((n, nbar), dtype=np.int64) - 999 # Initialize with marker value
        tasks = []
        columns_to_process = range(num_cols_to_solve)
        if single_column_mode:
            columns_to_process = [target_column_j]
        
        for j in columns_to_process:
            tasks.append((j, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx, args.bkz_block_size, args.bkz_float_type))

        start_solve_time = time.time()
        results_map = {}
        log.info("Starting parallel lattice reduction...")
        failed_jobs = {}
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                future_to_col = {executor.submit(solve_column_worker, task): task[0] for task in tasks}
                for future in concurrent.futures.as_completed(future_to_col):
                    col_j = future_to_col[future]
                    try:
                        _, s_j_unknown = future.result() # Get result (will raise exception if worker failed)
                        results_map[col_j] = s_j_unknown
                        log.info(f"Successfully processed column {col_j}.")
                    except Exception as exc:
                        log.error(f'Column {col_j} generated an exception: {exc}')
                        results_map[col_j] = None # Mark as failed in map
                        failed_jobs[col_j] = exc # Store exception
        except Exception as pool_exc:
            log.error(f"Error occurred in initial ProcessPoolExecutor: {pool_exc}")
            # Re-raise or handle pool-level failure
            raise pool_exc

        total_solve_time = time.time() - start_solve_time
        log.info(f"Initial parallel solving finished in {total_solve_time:.2f}s.")

        # --- Looping Retry for Failed Columns --- 
        failed_columns = [j for j in columns_to_process if results_map.get(j) is None]
        current_retry_block_size = args.bkz_block_size
        
        while failed_columns:
            next_block_size = current_retry_block_size * 2
            current_retry_block_size = next_block_size
            log.info(f"--- Retrying {len(failed_columns)} failed columns ({failed_columns}) with DOUBLED BKZ block size {current_retry_block_size} ---")
            
            retry_tasks = []
            # Only retry columns that failed without an exception initially, or handle specific exceptions if needed
            columns_to_retry_now = [j for j in failed_columns if j not in failed_jobs] 
            if not columns_to_retry_now:
                 log.warning("All failed columns had exceptions, cannot retry without specific handling. Aborting retry.")
                 break # Exit retry loop if all failures were exceptions
                 
            log.info(f"Preparing retry tasks for columns: {columns_to_retry_now}")
            for j in columns_to_retry_now:
                retry_tasks.append((j, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx, current_retry_block_size, args.bkz_float_type))
            
            num_retry_workers = min(args.workers if args.workers is not None else multiprocessing.cpu_count(), len(retry_tasks))
            start_retry_time = time.time()
            retry_failed_jobs = {} 
            try:
                with concurrent.futures.ProcessPoolExecutor(max_workers=num_retry_workers) as executor:
                    future_to_col_retry = {executor.submit(solve_column_worker, task): task[0] for task in retry_tasks}
                    for future in concurrent.futures.as_completed(future_to_col_retry):
                        col_j = future_to_col_retry[future]
                        try:
                            _, s_j_unknown_retry = future.result() # Will raise exception if worker failed
                            log.info(f"Successfully processed column {col_j} on RETRY (BKZ {current_retry_block_size}).")
                            results_map[col_j] = s_j_unknown_retry # Update map
                            if col_j in failed_jobs: del failed_jobs[col_j] # Remove from exception list if now successful
                        except Exception as exc:
                            log.error(f'Column {col_j} (RETRY BKZ {current_retry_block_size}) generated an exception: {exc}')
                            results_map[col_j] = None # Ensure marked as failed
                            retry_failed_jobs[col_j] = exc # Store retry exception
            except Exception as pool_exc:
                log.error(f"Error occurred in RETRY (BKZ {current_retry_block_size}) ProcessPoolExecutor: {pool_exc}")
                # Decide how to handle pool errors during retry, maybe break loop
                failed_jobs.update(retry_failed_jobs) # Keep track of failures
                break 
            
            failed_jobs.update(retry_failed_jobs) # Combine initial and retry exceptions
            total_retry_time = time.time() - start_retry_time
            log.info(f"Retry phase (BKZ {current_retry_block_size}) finished in {total_retry_time:.2f}s.")

            # Update the list of columns that still need solving (are None in results_map)
            failed_columns = [j for j in columns_to_process if results_map.get(j) is None] 
            # If only columns with exceptions remain, stop retrying them indefinitely
            if all(j in failed_jobs for j in failed_columns):
                 log.error(f"All remaining failed columns {failed_columns} encountered exceptions. Stopping retries.")
                 break
        
        # After loops, check if any columns ultimately failed
        final_failed_columns = [j for j in columns_to_process if results_map.get(j) is None]
        if final_failed_columns:
             log.error(f"Columns {final_failed_columns} failed to solve.")
             # Fail Close: Raise an exception summarizing the failures
             summary_message = "Failed to solve columns: " + ", ".join(map(str, final_failed_columns)) + ". "
             exception_details = " Exceptions: " + "; ".join([f"Col {j}: {type(e).__name__}(\"{e}\")" for j, e in failed_jobs.items()])
             raise RuntimeError(summary_message + exception_details)
        else:
             log.info("All columns successfully processed (potentially after retries).")

        # --- Reconstruct Final S Matrix --- 
        log.info("Reconstructing final S matrix (using s_unknown from worker)...") # Reverted log message
        all_solved = True 
        reconstruction_successful_cols = []

        # Use the same list of columns we intended to process
        for j in columns_to_process:
            s_j_unknown = results_map.get(j) # Get the s_unknown found by worker
            if s_j_unknown is not None:
                try:
                    s_j_known = S_known_matrix[:, j]
                    
                    # --- Log reconstruction details --- 
                    log.debug(f"--- Reconstruction Details for Column j={j} ---")
                    log.debug(f"  s_{j}_known[:10]:          {s_j_known[:10]}")
                    log.debug(f"  s_{j}_unknown[:10]:        {s_j_unknown[:10]}")
                    
                    # Restore the full reconstruction formula
                    s_j_recovered_raw = (s_j_known + modulus_approx * s_j_unknown) # Raw reconstruction
                    # Center the result mod q
                    s_j_final = np.where(s_j_recovered_raw % q >= q // 2, (s_j_recovered_raw % q) - q, s_j_recovered_raw % q)
                    log.debug(f"  s_{j}_recovered_raw[:10]:  {s_j_recovered_raw[:10]}")
                    log.debug(f"  s_{j}_final[:10]:          {s_j_final[:10]}")
                    
                    S_recovered_matrix[:, j] = s_j_final
                    log.info(f"Reconstructed column {j}.")
                    reconstruction_successful_cols.append(j)
                except Exception as recon_exc:
                    log.error(f"Error reconstructing column {j}: {recon_exc}")
                    log.exception("Reconstruction exception details:") 
                    all_solved = False # Mark as not fully solved
            else:
                all_solved = False 
                log.error(f"Column {j} data is missing in results_map. Final matrix incomplete.")

        if all_solved:
            log.info("Successfully reconstructed all attempted columns of S.")
            # --- Final Verification (Optional but Recommended) ---
            log.info("Performing final verification: Check if || B - AS || is small...")
            try:
                B_check = (A_np @ S_recovered_matrix[:, :num_cols_to_solve]) % q
                E_check = (B_np[:, :num_cols_to_solve] - B_check + q) % q
                E_check_signed = np.where(E_check >= q // 2, E_check - q, E_check)
                max_abs_error = np.max(np.abs(E_check_signed))
                mean_abs_error = np.mean(np.abs(E_check_signed))
                log.info(f"Verification Check: Max Abs Error = {max_abs_error}, Mean Abs Error = {mean_abs_error:.2f}")
                # Compare max_abs_error to expected Frodo error bounds
                frodo_max_expected_error_approx = 3 * kem.T_chi[-1] # Heuristic: 3 sigma? Check spec. Should be small (e.g. < 30)
                if max_abs_error <= frodo_max_expected_error_approx:
                    log.info("Recovered error matrix E seems small, S is likely correct.")
                else:
                    log.warning("Verification WARNING: Recovered error matrix E seems large. Solution might be incorrect.")
            except Exception as final_verify_exc:
                log.error(f"Error during final verification check: {final_verify_exc}")
        else:
            log.error("Reconstruction failed for some columns.")

        # --- Single Column Verification (if applicable) --- 
        if single_column_mode and target_column_j in reconstruction_successful_cols:
            log.info(f"--- Verifying recovered single column j={target_column_j} ---")
            try:
                b_j_original = B_np[:, target_column_j]
                s_j_recovered = S_recovered_matrix[:, target_column_j]
                
                # Calculate error e_j = b_j - A * s_j (mod q)
                As_j = (A_np @ s_j_recovered) % q
                e_j = (b_j_original - As_j + q) % q
                e_j_signed = np.where(e_j >= q // 2, e_j - q, e_j)
                
                max_abs_error = np.max(np.abs(e_j_signed))
                mean_abs_error = np.mean(np.abs(e_j_signed))
                std_dev_error = np.std(np.abs(e_j_signed))
                
                log.info(f"Single Column Verification (j={target_column_j}):")
                log.info(f"  Max Abs Error = {max_abs_error}")
                log.info(f"  Mean Abs Error = {mean_abs_error:.2f}")
                log.info(f"  Std Dev Abs Error = {std_dev_error:.2f}")
                
                # Compare max_abs_error to expected Frodo error bounds
                # Frodo error is Gaussian around 0 with std dev sigma_chi
                # T_chi is related, usually a small multiple of sigma_chi (e.g., 2 or 3)
                # Let's use a slightly generous bound, e.g., 6*sigma or check kem.T_chi
                # kem object might not be available here easily, let's use a heuristic based on q
                # Max error should be significantly smaller than q/2
                # A typical check might be if max_abs_error < q / 16 or similar
                verification_threshold = q // 16 
                if max_abs_error < verification_threshold:
                    log.info(f"Verification SUCCESS (j={target_column_j}): Recovered error seems small (Max Abs Error < {verification_threshold}).")
                else:
                    log.warning(f"Verification WARNING (j={target_column_j}): Recovered error seems large (Max Abs Error >= {verification_threshold}). Solution might be incorrect.")
                    
            except Exception as single_verify_exc:
                log.error(f"Error during single column verification check (j={target_column_j}): {single_verify_exc}")

        # --- Output Results ---
        # Save the recovered S matrix (potentially useful even if incomplete)
        output_S_filename = f"recovered_S_{args.uid}.npy"
        try:
            np.save(output_S_filename, S_recovered_matrix)
            log.info(f"Saved recovered S matrix (shape {S_recovered_matrix.shape}) to {output_S_filename}")
        except Exception as save_exc:
            log.error(f"Failed to save recovered S matrix: {save_exc}")

        # Display first few entries of recovered S
        print(f"\nRecovered S matrix (first 5 rows, {num_cols_to_solve} columns):")
        print(S_recovered_matrix[:5, :num_cols_to_solve])

        log.info("Solver script finished.")
        return S_recovered_matrix

    except Exception as e:
        log.exception(f"An error occurred in the main execution flow: {e}")
        # Re-raise the exception to ensure the script exits with non-zero status
        raise e

if __name__ == "__main__":
    import sys
    try:
        main()
        sys.exit(0) # Explicitly exit with 0 on success
    except Exception as e:
        # Logged in main, just exit with non-zero status
        sys.exit(1)
