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
def delta_thresh_to_S_known(delta_thresh: int, modulus: int) -> int:
    """
    Converts the observed threshold Δ* into S[k][l].

        Δ*  = smallest delta that flips the oracle
            = (-S) mod M     with  M = q / 2**B = 8192  for Frodo640

    Therefore           S = (-Δ*) mod M       and then centre to [-M/2, M/2).

    For Frodo640 this puts S in {-2,-1,0,1,2}.
    """
    if delta_thresh is None:
        log.warning("Encountered None for delta_thresh, returning 0")
        return 0

    # 1. negate  Δ*  modulo M
    centred = (-delta_thresh) % modulus           # 0 … M‑1

    # 2. centre into the interval  [‑M/2,  M/2)
    if centred >= modulus // 2:                   # 4096 … 8191  →  -4096 … -1
        centred -= modulus

    return centred  # now in {-2,…,2} for Frodo640


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
                      # Handle missing approximations if necessary (e.g., fill with zero, raise error)
                      log.warning(f"Missing approximation for S[{k}][{l}]. Using 0.")
                      S_known_matrix[k, l] = 0
                      missing_count += 1
                 else:
                      # !!! Apply the (placeholder) conversion !!!
                      S_known_matrix[k, l] = delta_thresh_to_S_known(delta_thresh, modulus_approx)
                 processed_count += 1
            else:
                log.warning(f"Ignoring approximation with out-of-bounds indices: ({k}, {l})")

        log.info(f"S_known_matrix (mod {modulus_approx}) constructed. Processed: {processed_count}, Missing: {missing_count}.")
        log.warning("Reminder: Conversion from delta_thresh to S_known is currently a PLACEHOLDER.")

    except Exception as e:
        log.error(f"Failed to construct S_known matrix: {e}")
        return None

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

        # Calculate A' = A (mod q) - Skip scaling by M
        log.debug(f"{worker_log_prefix} Setting A' = A % q ...")
        A_prime = A_np # Already mod q from prepare_matrices
        # A_prime = (modulus_approx * A_np) % q # Old scaling
        log.debug(f"{worker_log_prefix} Set A' = A.")

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
        # Use BKZ.reduction, params can be tuned
        # Pass float type string directly
        params = BKZ.Param(block_size=bkz_block_size, strategies=None, float_type=bkz_float_type, auto_abort=True)
        # Wrap reduction in a try-except block
        try:
             reduced_basis = BKZ.reduction(M, params)
             # reduced_basis = LLL.reduction(M) # LLL for faster test
        except Exception as e_bkz:
             log.error(f"{worker_log_prefix} BKZ reduction algorithm failed: {e_bkz}")
             return col_j, None
        duration = time.time() - start_time
        log.info(f"{worker_log_prefix} BKZ reduction finished in {duration:.2f}s.")

        # --- Extract Solution ---
        # Check first few vectors for the expected solution form.
        log.info(f"{worker_log_prefix} Analyzing first few vectors of reduced basis...")
        solution_s_unknown = None
        num_vectors_to_check = 5 # Reduced check range

        for i in range(min(num_vectors_to_check, n + 1)): 
            log.debug(f"{worker_log_prefix} Checking basis vector {i}")
            vector_list = [int(reduced_basis[i, c]) for c in range(n + 1)]
            candidate_vector = np.array(vector_list, dtype=np.int64)
            last_coord = candidate_vector[n]
            log.debug(f"{worker_log_prefix} Basis vector {i} last coord: {last_coord}") 

            # Check for exact solution vector (0,...,0, +/-1) first
            is_zero_vec = not np.any(candidate_vector[:n]) # Check if first n coords are zero
            if is_zero_vec and abs(last_coord) == 1:
                log.info(f"{worker_log_prefix} Found exact solution vector {i}: (0, ..., 0, {-last_coord})")
                potential_s_unknown = candidate_vector[:n] * (-last_coord) # Will be all zeros
                # Error check should be very small for this case if b' is small
                e_check = (A_prime @ potential_s_unknown - b_prime_j + q) % q 
                e_check_signed = np.where(e_check >= q // 2, e_check - q, e_check)
                max_abs_error = np.max(np.abs(e_check_signed))
                log.info(f"{worker_log_prefix} Exact Candidate {i} check: Max absolute error = {max_abs_error}")
                # Use a stricter check? Or assume this is the correct small error vector 'e = -bprime'
                if max_abs_error < q / 8: # Keep original check for now
                     log.info(f"{worker_log_prefix} Exact candidate vector {i} verified. Solution is 0.")
                     solution_s_unknown = potential_s_unknown
                     break
                else:
                    log.warning(f"{worker_log_prefix} Exact candidate {i} failed verification (error too large: {max_abs_error}). Should ideally be close to max(|b'|). Treating as failure.")
            elif abs(last_coord) == 1:
                # Check for the standard (s, +/-1) vector
                log.info(f"{worker_log_prefix} Found candidate vector {i} with last coord {-last_coord} (non-zero s part).")
                potential_s_unknown = candidate_vector[:n] * (-last_coord)

                # Verification step
                e_check = (A_prime @ potential_s_unknown - b_prime_j + q) % q
                e_check_signed = np.where(e_check >= q // 2, e_check - q, e_check)
                max_abs_error = np.max(np.abs(e_check_signed))
                log.info(f"{worker_log_prefix} Candidate {i} check: Max absolute error = {max_abs_error}") 

                # Heuristic check for small error 
                if max_abs_error < q / 8:
                    log.info(f"{worker_log_prefix} Candidate vector {i} verified (error seems small). Solution found.")
                    solution_s_unknown = potential_s_unknown
                    break # Stop searching once a valid solution is found
                else:
                    log.warning(f"{worker_log_prefix} Candidate vector {i} failed verification (error too large: {max_abs_error}).")

        if solution_s_unknown is None:
             log.warning(f"{worker_log_prefix} No suitable solution vector found in the first {num_vectors_to_check} basis vectors.")

    except Exception as e:
        log.exception(f"{worker_log_prefix} Unexpected error in worker: {e}") # Log full traceback
        return col_j, None

    return col_j, solution_s_unknown


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Solve FrodoKEM LWE instance using lattice reduction.")
    parser.add_argument("uid", type=str, help="User ID for which to load solver data.")
    parser.add_argument("--cols", type=int, default=None, help="Number of columns (0 to nbar-1) to solve (default: all).")
    parser.add_argument("-w", "--workers", type=int, default=None, help="Number of parallel workers (default: number of CPU cores).")
    parser.add_argument("--bkz-block-size", type=int, default=20, help="BKZ block size parameter (higher is slower but stronger).")
    # Add argument for float type precision if needed
    parser.add_argument("--bkz-float-type", choices=['d', 'dd', 'qd', 'mp'], default='mp', help="Floating point precision for BKZ (d=double, dd=double-double, qd=quad-double, mp=MPFR). 'mp' recommended.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set logging level.")
    parser.add_argument("--target-col", type=int, default=None, help="Solve only for a specific column index j.")
    args = parser.parse_args()

    log.setLevel(getattr(logging, args.log_level.upper()))

    # if not FPYLLL_AVAILABLE:
    #     log.error("fpylll library is required but not found. Please install it ('pip install fpylll').")
    #     return 1
    # if not FRODOKEM_AVAILABLE:
    #     log.error("frodokem.py module not found. Please ensure it's in the same directory or PYTHONPATH.")
    #     return 1

    # Load Data
    solver_data = load_solver_data(args.uid)
    if not solver_data:
        return 1

    # Prepare Matrices
    prep_result = prepare_matrices(solver_data)
    if not prep_result:
        return 1
    kem, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx = prep_result

    # --- [DEBUG] Compare S_known with S_true (if available and in single-col mode) --- 
    S_true_matrix = solver_data.get('S_true') # Get S_true if it exists
    S_true_np = None # Initialize S_true_np
    if S_true_matrix is not None:
        try:
            S_true_np_temp = np.array(S_true_matrix, dtype=np.int64)
            if S_true_np_temp.shape == (n, nbar):
                S_true_np = S_true_np_temp # Assign if valid format
                log.info("Successfully loaded S_true from pickle and converted to NumPy array.")
                # Perform the debug comparison only if target_col is specified
                if args.target_col is not None:
                    s_true_col = S_true_np[:, args.target_col]
                    s_known_col = S_known_matrix[:, args.target_col]
                    # Calculate true S mod M
                    s_true_mod_M = s_true_col % modulus_approx
                    
                    log.debug(f"--- Comparison for Column j={args.target_col} (mod {modulus_approx}) ---")
                    log.debug(f"  S_known[:10]: {s_known_col[:10]}")
                    log.debug(f"  S_true[:10] (mod M): {s_true_mod_M[:10]}")
                    
                    # Check for differences
                    diff = s_known_col - s_true_mod_M
                    mismatches = np.count_nonzero(diff % modulus_approx)
                    if mismatches == 0:
                        log.info(f"  SUCCESS: S_known column matches S_true column (mod {modulus_approx})!")
                    else:
                        log.warning(f"  MISMATCH: Found {mismatches} differences between S_known and S_true (mod {modulus_approx}).")
                        log.debug(f"  Difference[:10]: {diff[:10]}") # Show first few diffs
            else:
                log.warning("S_true matrix loaded from pickle but has unexpected shape. Will proceed without it.")
        except Exception as comp_ex:
            log.error(f"Error during S_true conversion or comparison: {comp_ex}. Will proceed without it.")
            S_true_np = None # Ensure S_true_np is None if conversion failed
    # --- End Debug Comparison --- 
    
    # --- Solver Bypass Logic REMOVED --- 
    # Always proceed with actual solver path
    log.info("Proceeding with actual solver path.")
    skip_solver = False
    # Initialize for actual solver run
    S_recovered_matrix = np.zeros((n, nbar), dtype=np.int64) - 999 
    all_solved = True # Assume true until a failure
    reconstruction_successful_cols = []
    results_map = {}

    # --- Parallel Solving (conditional) --- 
    # This block should now run if skip_solver is False
    if not skip_solver:
        # >>> UNCOMMENT THE ACTUAL SOLVER EXECUTION <<< 
        tasks = []
        columns_to_process = list(range(nbar)) # Default: solve all columns
        num_workers = args.workers if args.workers is not None else min(multiprocessing.cpu_count(), nbar)
        
        if args.target_col is not None:
            if 0 <= args.target_col < nbar:
                 columns_to_process = [args.target_col] # Override to solve only target column
                 log.info(f"--target-col specified: Solving only for column {args.target_col}")
                 num_workers = 1 # Use only 1 worker for single column mode
            else:
                 log.error(f"Invalid target column {args.target_col}. Must be between 0 and {nbar-1}. Exiting.")
                 return 1 # Exit if target column is invalid
        elif args.cols is not None: # Handle --cols argument if target-col is not set
            num_cols_to_solve = min(args.cols, nbar)
            columns_to_process = list(range(num_cols_to_solve))
            log.info(f"--cols specified: Solving first {num_cols_to_solve} columns.")
            num_workers = min(num_workers, num_cols_to_solve) # Adjust workers based on cols
        else:
             log.info(f"Solving all {nbar} columns.")
             num_workers = min(num_workers, nbar) # Adjust workers based on nbar

        log.info(f"Attempting to solve {len(columns_to_process)} columns using {num_workers} workers.")
        
        for j in columns_to_process:
            tasks.append((j, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx, args.bkz_block_size, args.bkz_float_type))
        
        if not tasks:
            log.warning("No tasks generated for the solver. Exiting.")
            return 1
            
        start_solve_time = time.time()
        log.info("Starting parallel lattice reduction...")
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
                future_to_col = {executor.submit(solve_column_worker, task): task[0] for task in tasks}
                for future in concurrent.futures.as_completed(future_to_col):
                    col_j = future_to_col[future]
                    try:
                        _, s_j_unknown = future.result() # Get result from worker
                        results_map[col_j] = s_j_unknown
                        if s_j_unknown is not None:
                            log.info(f"Successfully processed column {col_j}.")
                        else:
                            # Error logged within worker now
                            log.warning(f"Worker for column {col_j} returned None (solve likely failed).") 
                            all_solved = False # Mark as not fully solved if any worker fails
                    except Exception as exc:
                        log.error(f'Column {col_j} generated an exception during future.result(): {exc}')
                        results_map[col_j] = None
                        all_solved = False # Mark as not fully solved on exception
        except Exception as pool_exc:
            log.error(f"Error occurred in ProcessPoolExecutor: {pool_exc}")
            all_solved = False # Mark as not fully solved on pool error
        
        total_solve_time = time.time() - start_solve_time
        log.info(f"Parallel solving finished in {total_solve_time:.2f}s.")
        # >>> END OF UNCOMMENTED SOLVER <<< 
        # pass # Remove explicit pass

    # --- Reconstruct Final S Matrix --- 
    log.info("Reconstructing final S matrix from solver results...")
    reconstruction_successful_cols = [] # Initialize list for successfully reconstructed columns
    columns_to_attempt_reconstruction = list(range(nbar)) if args.target_col is None and args.cols is None else columns_to_process

    for j in columns_to_attempt_reconstruction:
        s_j_unknown = results_map.get(j) # Get result from solver run
        if s_j_unknown is not None:
            try:
                s_j_known = S_known_matrix[:, j]
                # Perform the actual reconstruction math
                s_j_recovered_raw = (s_j_known + modulus_approx * s_j_unknown) # Raw reconstruction
                s_j_final = np.where(s_j_recovered_raw % q >= q // 2, (s_j_recovered_raw % q) - q, s_j_recovered_raw % q)
                S_recovered_matrix[:, j] = s_j_final
                log.info(f"Reconstructed column {j}.") 
                reconstruction_successful_cols.append(j)
            except Exception as recon_exc:
                log.error(f"Error reconstructing column {j}: {recon_exc}")
                all_solved = False # Mark as not fully solved if reconstruction fails
        else:
            # If s_j_unknown is None, it means the solver failed for this column
            # We already set all_solved = False when the worker returned None or raised exception
            log.error(f"Column {j} data missing from solver results. Cannot reconstruct.")

    # --- Final Verification --- 
    log.info("Performing final verification: Check if || B - AS_recovered || is small...")
    try:
        B_check = (A_np @ S_recovered_matrix) % q 
        E_check = (B_np - B_check + q) % q
        E_check_signed = np.where(E_check >= q // 2, E_check - q, E_check)
        max_abs_error = np.max(np.abs(E_check_signed))
        mean_abs_error = np.mean(np.abs(E_check_signed))
        log.info(f"Verification Check: Max Abs Error = {max_abs_error}, Mean Abs Error = {mean_abs_error:.2f}")
        # Compare max_abs_error to expected Frodo error bounds
        # Define a reasonable threshold for max error magnitude
        max_expected_error_magnitude = 30 
        if max_abs_error <= max_expected_error_magnitude:
            log.info("Verification SUCCESS: Recovered error matrix E seems small, S is likely correct.")
        else:
            log.warning(f"Verification WARNING: Recovered error matrix E seems large (max error {max_abs_error} > {max_expected_error_magnitude}). Solution might be incorrect.")
    except Exception as final_verify_exc:
        log.error(f"Error during final verification check: {final_verify_exc}")

    # --- Output Results ---
    # Save the recovered S matrix (potentially useful even if incomplete)
    output_S_filename = f"recovered_S_{args.uid}.npy"
    try:
        np.save(output_S_filename, S_recovered_matrix)
        log.info(f"Saved recovered S matrix (shape {S_recovered_matrix.shape}) to {output_S_filename}")
    except Exception as save_exc:
        log.error(f"Failed to save recovered S matrix: {save_exc}")

    # Display first few entries of recovered S
    print(f"\nRecovered S matrix (first 5 rows, {len(reconstruction_successful_cols)} columns):")
    print(S_recovered_matrix[:5, reconstruction_successful_cols])

    log.info("Solver script finished.")
    return 0 if all_solved else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())