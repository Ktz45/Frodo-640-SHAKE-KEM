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
    """Loads pk_hex and sk_hex from the student file."""
    filename = os.path.join('student_files', f"{uid}.txt")
    log.info(f"Loading data from student file: {filename}")
    if not os.path.exists(filename):
        log.error(f"Student file not found: {filename}")
        return None, None
    try:
        with open(filename, 'r') as file:
            content = file.read()
            # Assuming PK is needed for KEM init indirectly via sk parsing if needed
            # pk_hex = content.split('Public Key: ')[1].split('\n')[0]
            sk_hex = content.split('Secret Key: ')[1].split('\n')[0]
            log.info("Successfully loaded SK hex.")
            return sk_hex # Only need sk_hex for S parsing
    except Exception as e:
        log.error(f"Error reading or parsing student file {filename}: {e}")
        return None

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
                Stransposed[i][j] = Sbytes_stream.read('intle:16') # Use intle:16 for signed
        
        # Transpose S^T to get S (n x nbar)
        S_true_list = [[Stransposed[j][i] for j in range(kem.nbar)] for i in range(kem.n)]
        S_true_np = np.array(S_true_list, dtype=np.int64) # Use int64 for potential negative values
        log.info(f"Successfully parsed true S matrix ({S_true_np.shape}).")
        return S_true_np
            
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
        max_val = np.max(np.abs(matrix[comparison_results != 0])) if np.any(comparison_results != 0) else 0
        min_val = np.min(matrix[comparison_results != 0]) if np.any(comparison_results != 0) else 0
        # Handle case where only -999 exists
        if np.all(matrix == -999):
             max_width = 4
        else:
             max_width = max(len(str(max_val)), len(str(min_val)), 4) # Min width 4 for -999
        
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
                comp_res = comparison_results[i, j]
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
    parser.add_argument("-u", "--uid", type=str, required=True, help="User ID for loading the true secret key.")
    parser.add_argument("-c", "--column", type=int, default=None, help="Optional: Index of a single column to compare and highlight.")
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
    sk_hex = load_student_data(args.uid)
    if sk_hex is None:
        return
    S_true_np = parse_true_S(kem, sk_hex)
    if S_true_np is None:
        return
        
    # --- Validate Shapes ---
    if S_recovered_np.shape != S_true_np.shape:
        log.error(f"Shape mismatch! Recovered: {S_recovered_np.shape}, True: {S_true_np.shape}")
        return
    rows, cols = S_recovered_np.shape

    # --- Compare Columns & Prepare Comparison Matrix ---
    log.info("--- Comparing Recovered Columns with True Columns --- ")
    # 0 = unsolved/placeholder, 1 = match, -1 = mismatch
    comparison_results = np.zeros_like(S_recovered_np, dtype=int)
    all_match = True
    solved_count = 0
    columns_to_check = []
    
    if args.column is not None:
        # Single column mode
        if 0 <= args.column < cols:
            log.info(f"Targeting single column: {args.column}")
            columns_to_check = [args.column]
        else:
            log.error(f"Invalid target column {args.column}. Must be between 0 and {cols-1}. Skipping comparison.")
            # Leave comparison_results as zeros
    else:
        # All columns mode (default)
        log.info("Comparing all columns.")
        columns_to_check = range(cols)
        
    for j in columns_to_check:
        recovered_col = S_recovered_np[:, j]
        true_col = S_true_np[:, j]
        # Check if column contains the placeholder
        is_solved = not np.any(recovered_col == -999)
        
        if is_solved:
            # Only count solved columns if checking all
            if args.column is None: 
                 solved_count += 1 
                 
            col_match = np.array_equal(recovered_col, true_col)
            if col_match:
                log.info(f"Column {j}: MATCH")
                comparison_results[:, j] = 1 # Mark column as matching
            else:
                log.error(f"Column {j}: MISMATCH")
                all_match = False
                # Mark specific mismatching cells
                comparison_results[:, j] = np.where(recovered_col == true_col, 1, -1)
                # Optional: Log first few differing values
                diff_indices = np.where(recovered_col != true_col)[0]
                log.error(f"  First few differences at rows: {diff_indices[:5]}")
                for row_idx in diff_indices[:5]:
                     log.error(f"    Row {row_idx}: Rec={recovered_col[row_idx]}, True={true_col[row_idx]}")
        else:
            log.info(f"Column {j}: Contains placeholder value (-999), skipping comparison.")
            # If we are checking all columns, finding an unsolved one means not all match
            if args.column is None:
                 all_match = False 
                     
    # Only print summary if checking all columns
    if args.column is None:                 
        log.info("--- Comparison Summary ---")
        log.info(f"Compared {solved_count}/{cols} columns (excluding placeholders).")
        if solved_count == 0:
             log.warning("No solved columns found to compare.")
        elif all_match:
             log.info("Overall Result: SUCCESS - All solved columns match the true secret!")
        else:
             log.error("Overall Result: FAILURE - At least one solved column does NOT match the true secret (or some columns were not solved).")

    # --- Print Matrix with Highlights ---
    print("\nPrinting Recovered Matrix (Green=Match, Red=Mismatch, No Highlight=Unsolved):")
    print_comparison_matrix(S_recovered_np, comparison_results)

if __name__ == "__main__":
    main() 