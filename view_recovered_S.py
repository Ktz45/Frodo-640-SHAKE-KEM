import numpy as np
import argparse
import os
import logging
import bitstring

from frodokem import FrodoKEM

# --- Constants ---
VARIANT = "FrodoKEM-640-SHAKE"
# ANSI escape codes for highlighting
GREEN = '\033[42m'  # Green background
RED   = '\033[41m'  # Red background
RESET = '\033[0m'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("VerifyView")

def load_student_data(uid):
    """Loads sk_hex from the student file."""
    filename = os.path.join('student_files', f"{uid}.txt")
    log.info(f"Loading data from student file: {filename}")
    if not os.path.exists(filename):
        log.error(f"Student file not found: {filename}")
        return None
    try:
        with open(filename, 'r') as file:
            content = file.read()
            # Find the line starting with Secret Key: and extract hex
            sk_hex = None
            for line in content.splitlines():
                if line.startswith("Secret Key:"):
                    # Strip label and potential whitespace, take the rest
                    sk_hex = line.split("Secret Key:", 1)[1].strip()
                    break # Found it
            
            if sk_hex:
                log.info("Successfully loaded SK hex.")
                # Debug: Print length and start/end
                log.debug(f"Loaded sk_hex length: {len(sk_hex)}")
                log.debug(f"Loaded sk_hex starts: {sk_hex[:64]}...")
                log.debug(f"Loaded sk_hex ends: ...{sk_hex[-64:]}")
                return sk_hex
            else:
                log.error(f"Could not find 'Secret Key:' line in {filename}")
                return None
    except Exception as e:
        log.error(f"Error reading or parsing student file {filename}: {e}")
        return None

def parse_true_S(kem: FrodoKEM, sk_hex: str) -> np.ndarray | None:
    """Parses the true S matrix from the full secret key hex."""
    log.info("Parsing true S matrix from secret key hex...")
    try:
        sk_bytes = bytes.fromhex(sk_hex)
        if len(sk_bytes) != kem.len_sk_bytes:
            log.error(f"SK length mismatch! Actual: {len(sk_bytes)} bytes ({len(sk_hex)} hex), Expected: {kem.len_sk_bytes} bytes.")
            return None

        # Calculate offset and length for S^T based on KEM parameters
        # sk = s || seedA || b || S^T || pkh
        offset_s = 0
        len_s = kem.len_s_bytes
        offset_seedA = offset_s + len_s
        len_seedA = kem.len_seedA_bytes
        offset_b = offset_seedA + len_seedA
        len_b = int(kem.D * kem.n * kem.nbar / 8)
        offset_St = offset_b + len_b
        len_St = int(kem.n * kem.nbar * 16 / 8) # 16 bits per element
        offset_pkh = offset_St + len_St
        len_pkh = kem.len_pkh_bytes
        
        # Assert total length matches
        assert offset_pkh + len_pkh == kem.len_sk_bytes, "Internal length calculation mismatch!"
        
        log.debug(f"Calculated S^T offset: {offset_St}, length: {len_St}")

        if offset_St + len_St > len(sk_bytes):
            log.error("Calculated offset/length for S^T exceeds secret key bounds.")
            return None
            
        Sbytes_stream = bitstring.ConstBitStream(sk_bytes[offset_St : offset_St + len_St])

        Stransposed = [[0 for _ in range(kem.n)] for _ in range(kem.nbar)]
        for i in range(kem.nbar):
            for j in range(kem.n):
                Stransposed[i][j] = Sbytes_stream.read('intle:16') # Use intle:16 for signed
        
        # Transpose S^T to get S (n x nbar)
        S_true_list = [[Stransposed[j][i] for j in range(kem.nbar)] for i in range(kem.n)]
        S_true_np = np.array(S_true_list, dtype=np.int64) # Use int64 for potential negative values
        log.info(f"Successfully parsed true S matrix ({S_true_np.shape}) from sk_hex.")
        return S_true_np
            
    except ValueError as e:
        log.error(f"Error decoding secret key hex: {e}. Is it valid hex?")
        return None
    except Exception as e:
        log.error(f"Error parsing true S from secret key hex: {e}")
        return None

def print_comparison_matrix(matrix, comparison_results):
    """Prints the matrix, highlighting cells based on comparison results."""
    if matrix is None or comparison_results is None:
        log.error("Matrix or comparison results are None.")
        return
        
    try:
        rows, cols = matrix.shape
        if matrix.shape != comparison_results.shape:
            log.error("Matrix and comparison results shapes do not match!")
            return
            
        log.info(f"Displaying Matrix shape: ({rows}x{cols})")

        # Determine max width for number formatting
        # Handle case where only 0 or None might exist if comparison fails early
        non_placeholder_elements = matrix[comparison_results != 0] if comparison_results is not None else matrix
        
        # Check if non_placeholder_elements is empty or contains only zeros before calculating max/min
        if non_placeholder_elements is not None and non_placeholder_elements.size > 0 and np.any(non_placeholder_elements):
             max_val = np.max(np.abs(non_placeholder_elements))
             min_val = np.min(non_placeholder_elements) # Check min on potentially signed values
             max_width = max(len(str(max_val)), len(str(min_val)), 4) # Min width 4 for -999 or default
        else: # Handle case with no mismatches or empty matrix
             max_width = 4 # Default width
        
        # Print header
        header = "Row |" + "".join([f"{str(j).center(max_width + 3)}" for j in range(cols)])
        print(header)
        print("-" * len(header))

        # Print rows (limiting rows for display if too large)
        max_rows_to_print = 50 # Adjust as needed
        rows_to_print = min(rows, max_rows_to_print)
        
        for i in range(rows_to_print):
            row_str = f"{str(i).ljust(3)} |"
            for j in range(cols):
                val = matrix[i, j]
                # Handle case where comparison_results might be None if shapes mismatch
                comp_res = comparison_results[i, j] if comparison_results is not None else 0
                formatted_val = str(val).rjust(max_width)
                
                if comp_res == 1: # Match
                    row_str += f" {GREEN}{formatted_val}{RESET}  "
                elif comp_res == -1: # Mismatch
                    row_str += f" {RED}{formatted_val}{RESET}  "
                else: # Unsolved
                    row_str += f" {formatted_val}  "
            print(row_str)
        
        if rows > max_rows_to_print:
            print(f"... (truncated - showing first {max_rows_to_print} of {rows} rows) ...")
            
    except Exception as e:
        log.exception(f"Error printing matrix: {e}") # Log full traceback

def main():
    parser = argparse.ArgumentParser(description="Load recovered S matrix, compare solved columns with true S matrix, and print with highlights.")
    parser.add_argument("npy_file", help="Path to the .npy file containing the recovered S matrix.")
    parser.add_argument("-u", "--uid", type=str, required=True, help="User ID for loading the true secret key from student file.")
    args = parser.parse_args()

    # --- Load Recovered S ---
    if not os.path.exists(args.npy_file):
        log.error(f"Recovered S file not found: {args.npy_file}")
        return
    try:
        log.info(f"Loading recovered S from: {args.npy_file}")
        S_recovered_np = np.load(args.npy_file)
        log.info(f"Recovered S matrix shape: {S_recovered_np.shape}")
    except Exception as e:
        log.error(f"Error loading recovered S file: {e}")
        return
        
    # --- Load True S ---
    kem = FrodoKEM(VARIANT) # Initialize KEM to get params
    # --- Use student file loading and parsing ---
    sk_hex = load_student_data(args.uid)
    if sk_hex is None:
        return # Error already logged
    S_true_np = parse_true_S(kem, sk_hex)
    if S_true_np is None:
        return # Error already logged
        
    # --- Print Parsed True S for Debug ---
    log.info("--- Parsed True S Matrix (from Student File - First 5x8) ---")
    try:
        print(S_true_np[:5, :]) # Print first 5 rows, all columns
    except Exception as e:
        log.error(f"Error printing parsed S_true: {e}")
    # ---------------------------------------
        
    # --- Immediate Comparison Debug --- 
    log.info("--- Immediate Comparison --- ")
    try:
        val_rec = S_recovered_np[0, 0]
        dtype_rec = S_recovered_np.dtype
        val_true = S_true_np[0, 0]
        dtype_true = S_true_np.dtype
        log.info(f"Recovered[0,0]: {val_rec} (dtype: {dtype_rec})")
        log.info(f"Parsed True[0,0]: {val_true} (dtype: {dtype_true})")
        if val_rec == val_true and dtype_rec == dtype_true:
             log.info("First element MATCHES.")
        else:
             log.error("First element MISMATCH.")
             
        if np.array_equal(S_recovered_np, S_true_np):
            log.info("np.array_equal confirms: MATRICES ARE EQUAL")
        else:
            log.error("np.array_equal confirms: MATRICES ARE DIFFERENT")
            # Find first difference
            diff_indices = np.where(S_recovered_np != S_true_np)
            if len(diff_indices[0]) > 0:
                r, c = diff_indices[0][0], diff_indices[1][0]
                log.error(f"First difference at index ({r},{c}): Rec={S_recovered_np[r,c]}, True={S_true_np[r,c]}")
            
    except Exception as e:
        log.error(f"Error during immediate comparison: {e}")
    # --- End Immediate Comparison --- 

    # --- Validate Shapes ---
    if S_recovered_np.shape != S_true_np.shape:
        log.error(f"Shape mismatch! Recovered: {S_recovered_np.shape}, True: {S_true_np.shape}")
        return
    rows, cols = S_recovered_np.shape

    # --- Compare Matrices & Prepare Comparison Matrix ---
    log.info("Comparing Recovered S with True S (from student file)... ")
    comparison_results = np.zeros_like(S_recovered_np, dtype=int)
    
    match_mask = (S_recovered_np == S_true_np)
    mismatch_mask = ~match_mask
    
    comparison_results[match_mask] = 1  # 1 for match
    comparison_results[mismatch_mask] = -1 # -1 for mismatch
    
    num_matches = np.sum(match_mask)
    num_mismatches = np.sum(mismatch_mask)
    total_elements = S_recovered_np.size
    
    log.info(f"Comparison complete: Matches={num_matches}, Mismatches={num_mismatches} (Total={total_elements})")
    
    # --- Print Mismatch Details --- 
    if num_mismatches > 0:
        log.warning("--- Mismatch Details (Index: Recovered vs True) ---")
        mismatch_indices = np.where(mismatch_mask)
        # Limit number of mismatches printed to avoid flooding logs
        max_mismatches_to_print = 100 
        for i in range(min(num_mismatches, max_mismatches_to_print)):
            r, c = mismatch_indices[0][i], mismatch_indices[1][i]
            log.warning(f"  ({r},{c}): {RED}{S_recovered_np[r, c]}{RESET} vs {GREEN}{S_true_np[r, c]}{RESET}")
        if num_mismatches > max_mismatches_to_print:
            log.warning(f"  ... (truncated - showing first {max_mismatches_to_print} mismatches) ...")
    # ----------------------------- 

    # --- Print Matrix with Highlights ---
    log.info("Displaying comparison matrix (Green=Match, Red=Mismatch)")
    print_comparison_matrix(S_recovered_np, comparison_results) # Use the full comparison

if __name__ == "__main__":
    main() 