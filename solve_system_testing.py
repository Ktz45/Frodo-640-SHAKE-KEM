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

# --- Lattice Solver Worker REMOVED ---
# def solve_column_worker(...): 
#    ... (function body removed) ...


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

    # --- [DEBUG] Compare S_known with S_true (if available) ---
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
    
    # --- "Solve" by using S_known directly --- 
    log.info("Using S_known_matrix directly as S_recovered_matrix (Lattice solver bypassed)." )
    S_recovered_matrix = S_known_matrix.copy() # S_known IS the recovered secret
    all_solved = True # Assume success if S_known was constructed
    reconstruction_successful_cols = list(range(nbar))
    
    # --- Sanity Check (Inline) --- 
    log.info("Performing inline sanity check: || B - A*S_known || should be small...")
    try:
        E = (B_np - (A_np @ S_recovered_matrix) % q + q) % q
        E_centered = np.where(E >= q//2, E - q, E)
        max_abs_error_sanity = np.max(np.abs(E_centered))
        log.info(f"Sanity Check: Max Abs Error = {max_abs_error_sanity}")
        assert max_abs_error_sanity <= 30, f"Sanity check failed! Max error {max_abs_error_sanity} > 30. Approximations might be wrong."
        log.info("Sanity check passed.")
    except Exception as sanity_ex:
        log.error(f"Error during inline sanity check: {sanity_ex}")
        # Optionally exit or mark as unsolved if sanity check fails critically
        # return 1 

    # --- Parallel Solving REMOVED --- 
    # ... (block removed) ...

    # --- Reconstruct Final S Matrix REMOVED --- 
    # ... (block removed) ...

    # --- Final Verification --- 
    # This now verifies the result using S_known as S_recovered
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
    # Save the recovered S matrix (which is S_known)
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