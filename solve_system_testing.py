import pickle
import os
import numpy as np
import concurrent.futures
import multiprocessing
import time
import logging
import argparse
from typing import Tuple, Optional, List, Dict, Any

# Attempt to import fpylll, provide guidance if missing
try:
    from fpylll import IntegerMatrix, LLL, BKZ, FP_NR # FP_NR for floating point type
    FPYLLL_AVAILABLE = True
except ImportError:
    FPYLLL_AVAILABLE = False
    # Define dummy classes if fpylll not found, so script can load/parse args
    class IntegerMatrix: pass
    class LLL: pass
    class BKZ: Param=None; DEFAULT_STRATEGY=None; reduction=None
    FP_NR = None

# Assuming frodokem.py is in the same directory or PYTHONPATH
try:
    from frodokem import FrodoKEM
    FRODOKEM_AVAILABLE = True
except ImportError:
    FRODOKEM_AVAILABLE = False
    # Dummy class if frodokem not found
    class FrodoKEM: pass

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
    Converts the observed delta_threshold to S[k][l] mod modulus_approx.
    !!! WARNING: THIS IS A CRITICAL PLACEHOLDER !!!
    The correct conversion depends on a precise mathematical analysis of
    which rounding boundary is crossed by (delta - S[k,l]).
    Assuming delta_thresh = (boundary - (-S_kl)) mod q implies
    delta_thresh = (boundary + S_kl) mod q. If boundary=q/4,
    S_kl = (delta_thresh - q/4) mod q. Then S_kl mod M = (delta_thresh - q/4) mod M.
    Let's use S_kl = -delta_thresh mod M for now as a simple placeholder.
    """
    if delta_thresh is None:
      log.warning("Encountered None for delta_thresh, returning 0")
      return 0
    # Placeholder logic:
    s_kl_known_mod = (-delta_thresh + modulus) % modulus
    # log.debug(f"Converting delta={delta_thresh} to S_known={s_kl_known_mod} (mod {modulus})")
    return s_kl_known_mod

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
    if not FRODOKEM_AVAILABLE:
        log.error("FrodoKEM library not found. Cannot generate Matrix A.")
        return None

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
def solve_column_worker(args: Tuple[int, np.ndarray, np.ndarray, np.ndarray, int, int, int, int, int, float]) -> Tuple[int, Optional[np.ndarray]]:
    """Solves for one column s_j_unknown using lattice reduction."""
    col_j, A_np, B_np, S_known_matrix_np, q, n, nbar, modulus_approx, bkz_block_size, bkz_float_type = args
    worker_log_prefix = f"[Worker {col_j}]"
    log.info(f"{worker_log_prefix} Starting...")

    if not FPYLLL_AVAILABLE:
        log.error(f"{worker_log_prefix} fpylll library not found. Cannot perform lattice reduction.")
        return col_j, None

    try:
        # Calculate target vector b'_j = (b_j - A * s_{j,known}) mod q
        s_j_known = S_known_matrix_np[:, col_j]
        b_j = B_np[:, col_j]
        log.debug(f"{worker_log_prefix} Calculating A * s_j_known...")
        A_s_j_known = (A_np @ s_j_known) % q
        b_prime_j = (b_j - A_s_j_known + q) % q # Ensure positive result
        log.debug(f"{worker_log_prefix} Calculated b'_j.")

        # Calculate A' = (modulus_approx * A) mod q
        log.debug(f"{worker_log_prefix} Calculating A' = {modulus_approx} * A...")
        A_prime = (modulus_approx * A_np) % q
        log.debug(f"{worker_log_prefix} Calculated A'.")

        # --- Construct the Lattice Basis ---
        # Using the Primal Attack embedding: find short vector in basis derived from:
        # [ A'   b'_j ]
        # [ qI    0  ]
        # We want the vector (s_unknown, -1) such that B * (s_unknown, -1)^T is short.
        # Check literature for exact basis - common form is often transposed.
        # Let's try basis B = [[A', qI], [b'_j, 0]] - dimension (n) x (n+1) ? No.
        # Need a square basis. Standard embedding for u such that Au=b mod q:
        # Basis Dim = n + 1 = 641
        #     n   1
        # [   I   0  ] n
        # [   A'  b' ] 1 <-- target vector related to error? No.
        # [   0   q  ] n <-- A' from lwe?

        # Trying standard search-LWE basis: find (s, e) st A's - b' = -e mod q
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
        params = BKZ.Param(block_size=bkz_block_size, strategies=BKZ.DEFAULT_STRATEGY, float_type=bkz_float_type, auto_abort=True)
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
        # For this lattice basis construction B = [[A', b'], [0, q]],
        # the target solution vector related to (s_unknown, -1) should be short.
        # v = B * (s_unknown, -1)^T = (A's_unknown - b', -q)^T = (-e, -q)^T
        # So we look for short vectors in the reduced basis.
        # The first vector is often the shortest non-zero vector.
        log.info(f"{worker_log_prefix} Analyzing reduced basis...")
        solution_s_unknown = None
        # Convert first row (vector) of the reduced basis to numpy array
        # Note: reduced_basis is IntegerMatrix, access elements directly
        first_vector_list = [int(reduced_basis[0, c]) for c in range(n + 1)]
        candidate_vector = np.array(first_vector_list, dtype=np.int64)

        # We expect the solution vector to correspond to (s_unknown, -1) when multiplied by the basis transformation matrix U.
        # A simpler check (heuristic): In LWE attacks, the solution often appears directly
        # as a vector whose last coordinate is small (e.g., +/- 1) after reduction.
        # Check if the first vector *itself* has the form (s_unknown, +/- 1). Needs verification.

        # Let's assume the construction yields a vector v = (s_unknown, -1) in the lattice.
        # Check the last element of the candidate vector:
        last_coord = candidate_vector[n]
        if abs(last_coord) == 1:
            log.info(f"{worker_log_prefix} Found candidate vector with last coord {-last_coord}.")
            # If last coord is -1, first n coords are s_unknown.
            # If last coord is 1, first n coords are -s_unknown.
            potential_s_unknown = candidate_vector[:n] * (-last_coord)

            # Verification step (optional but recommended): Check if error is small
            e_check = (A_prime @ potential_s_unknown - b_prime_j + q) % q
            # Convert to signed integers centered around 0
            e_check_signed = np.where(e_check >= q // 2, e_check - q, e_check)
            max_abs_error = np.max(np.abs(e_check_signed))
            log.info(f"{worker_log_prefix} Candidate solution check: Max absolute error = {max_abs_error}")
            # Check if max_abs_error is within expected bounds for FrodoKEM error dist.
            # This threshold needs tuning based on Frodo spec. Let's use a loose check for now.
            if max_abs_error < q / 8: # Heuristic check
                log.info(f"{worker_log_prefix} Candidate solution verified (error seems small).")
                solution_s_unknown = potential_s_unknown
            else:
                log.warning(f"{worker_log_prefix} Candidate solution failed verification (error too large: {max_abs_error}).")
        else:
            log.warning(f"{worker_log_prefix} First vector of reduced basis doesn't seem to be solution (last coord: {last_coord}). Further analysis or higher BKZ block size might be needed.")
            # You might need to check other vectors in reduced_basis[:k]

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
    args = parser.parse_args()

    log.setLevel(getattr(logging, args.log_level.upper()))

    if not FPYLLL_AVAILABLE:
        log.error("fpylll library is required but not found. Please install it ('pip install fpylll').")
        return 1
    if not FRODOKEM_AVAILABLE:
        log.error("frodokem.py module not found. Please ensure it's in the same directory or PYTHONPATH.")
        return 1

    # Load Data
    solver_data = load_solver_data(args.uid)
    if not solver_data:
        return 1

    # Prepare Matrices
    prep_result = prepare_matrices(solver_data)
    if not prep_result:
        return 1
    kem, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx = prep_result

    # Determine columns and workers
    num_cols_to_solve = args.cols if args.cols is not None and args.cols <= nbar else nbar
    num_workers = args.workers if args.workers is not None else multiprocessing.cpu_count()
    num_workers = min(num_workers, num_cols_to_solve) # No need for more workers than columns
    log.info(f"Attempting to solve first {num_cols_to_solve} columns using {num_workers} workers.")
    log.info(f"BKZ Parameters: Block Size = {args.bkz_block_size}, Float Type = {args.bkz_float_type}")

    # Select float type for BKZ
    float_type = FP_NR(53) # Default to double
    if args.bkz_float_type == 'dd':
         float_type = FP_NR(106)
    elif args.bkz_float_type == 'qd':
         float_type = FP_NR(212)
    elif args.bkz_float_type == 'mp':
         # Choose a suitable precision for MPFR, e.g., 250 bits
         float_type = FP_NR(250)

    # --- Parallel Solving ---
    S_recovered_matrix = np.zeros((n, nbar), dtype=np.int64) - 999 # Initialize with marker value
    tasks = []
    for j in range(num_cols_to_solve):
        tasks.append((j, A_np, B_np, S_known_matrix, q, n, nbar, modulus_approx, args.bkz_block_size, float_type))

    start_solve_time = time.time()
    results_map = {}
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
                        log.error(f"Failed to find solution for column {col_j}.")
                except Exception as exc:
                    log.error(f'Column {col_j} generated an exception during future.result(): {exc}')
                    results_map[col_j] = None
    except Exception as pool_exc:
        log.error(f"Error occurred in ProcessPoolExecutor: {pool_exc}")

    total_solve_time = time.time() - start_solve_time
    log.info(f"Parallel solving finished in {total_solve_time:.2f}s.")

    # --- Reconstruct Final S Matrix ---
    log.info("Reconstructing final S matrix...")
    all_solved = True
    for j in range(num_cols_to_solve):
        s_j_unknown = results_map.get(j)
        if s_j_unknown is not None:
            try:
                s_j_known = S_known_matrix[:, j]
                # Final result s_j = s_known + M * s_unknown (potentially mod q ?)
                # The recovered s_j should ideally have small coefficients matching Frodo spec
                s_j_recovered = (s_j_known + modulus_approx * s_j_unknown) # Raw reconstruction

                # Convert to signed integers mod q, centered around 0
                s_j_final = np.where(s_j_recovered % q >= q // 2, (s_j_recovered % q) - q, s_j_recovered % q)

                S_recovered_matrix[:, j] = s_j_final
                log.info(f"Reconstructed column {j}.")
            except Exception as recon_exc:
                log.error(f"Error reconstructing column {j}: {recon_exc}")
                all_solved = False
        else:
            all_solved = False
            log.error(f"Column {j} data is missing. Final matrix will be incomplete.")

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
                log.info("Verification SUCCESS: Recovered error matrix E seems small, S is likely correct.")
            else:
                log.warning("Verification WARNING: Recovered error matrix E seems large. Solution might be incorrect.")
        except Exception as final_verify_exc:
            log.error(f"Error during final verification check: {final_verify_exc}")
    else:
        log.error("Failed to recover all attempted columns of S. Cannot verify.")

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
    return 0 if all_solved else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
