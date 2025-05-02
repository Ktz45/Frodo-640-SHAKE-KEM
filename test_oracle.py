import logging
import binascii
from frodokem import FrodoKEM
from local_server import LocalServer

# --- Constants ---
VARIANT = "FrodoKEM-640-SHAKE"
UID = '119008041' # Use the same UID
# Use the corrected salt length (32 bytes = 64 hex zeros)
SALT_HEX = "0" * 64 
BYTES_SALT = bytes.fromhex(SALT_HEX)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("OracleTest")

def run_test():
    log.info("--- Starting Oracle Test ---")
    try:
        # --- Setup ---
        log.info(f"Setting up server for UID: {UID}")
        server = LocalServer(determ=False) # Use non-deterministic for encapsulation
        kem = FrodoKEM(VARIANT)
        
        # Verify salt length against KEM spec
        if len(BYTES_SALT) != kem.len_salt_bytes:
             raise ValueError(f"Salt length mismatch. Provided: {len(BYTES_SALT)*2} hex chars, KEM expects: {kem.len_salt_bytes}.")

        server.check_server()
        pk_hex, _, _ = server.call_first_interface(UID)
        pk_bytes = bytes.fromhex(pk_hex)
        log.info(f"Received PK hex: {pk_hex[:10]}...")

        # --- Generate Base Ciphertext ---
        log.info("Generating a base ciphertext using kem_encaps...")
        ct_base_bytes, ss_base_bytes = kem.kem_encaps(pk_bytes)
        
        # Ensure the generated CT uses the correct salt length for later comparison
        c1_len = kem.mbar * kem.n * kem.D // 8
        c2_len = kem.mbar * kem.nbar * kem.D // 8
        ct_base_bytes = ct_base_bytes[:c1_len + c2_len] + BYTES_SALT # Enforce correct salt
        
        ct1_hex = ct_base_bytes.hex().upper()
        log.info(f"Base CT1 hex: {ct1_hex[:10]}...")

        # --- Create Modified Ciphertext ---
        log.info("Creating modified ciphertext (changing one byte in c2)...")
        c1_bytes = ct_base_bytes[:c1_len]
        c2_bytes = ct_base_bytes[c1_len : c1_len + c2_len]
        salt_bytes = ct_base_bytes[c1_len + c2_len :]

        if len(c2_bytes) == 0:
            log.error("Cannot modify c2, its length is zero.")
            return

        # Modify the first byte of c2
        c2_modified_list = list(c2_bytes)
        c2_modified_list[0] = (c2_modified_list[0] + 1) % 256
        c2_modified_bytes = bytes(c2_modified_list)

        ct2_bytes = c1_bytes + c2_modified_bytes + salt_bytes
        ct2_hex = ct2_bytes.hex().upper()
        log.info(f"Modified CT2 hex: {ct2_hex[:10]}...")
        
        # --- Query Oracle ---
        log.info(f"Querying oracle with CT1...")
        aes_ct1_hex = server.call_second_interface(UID, ct1_hex)
        log.info(f"Oracle response 1: {aes_ct1_hex}")

        log.info(f"Querying oracle with CT2...")
        aes_ct2_hex = server.call_second_interface(UID, ct2_hex)
        log.info(f"Oracle response 2: {aes_ct2_hex}")

        # --- Compare Results ---
        if aes_ct1_hex != aes_ct2_hex:
            log.info("SUCCESS: Oracle produced different outputs for different ciphertexts.")
        else:
            log.error("FAILURE: Oracle produced the SAME output for different ciphertexts. Oracle might be broken.")

    except Exception as e:
        log.exception(f"An error occurred during the test: {e}")

if __name__ == "__main__":
    run_test() 