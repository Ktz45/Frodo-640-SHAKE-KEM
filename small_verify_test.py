import pickle, solve_system_testing, attack_solver, os
from local_server import LocalServer
from frodokem import FrodoKEM

UID = "119008041"                 # <-- your uid
PICKLE = f"solver_inputs/solver_inputs_{UID}.pkl"

# ------------------------------------------------------------------
#  A)  load the previously stored data (seedA, B, Δ-thresholds …)
# ------------------------------------------------------------------
solver_data = pickle.load(open(PICKLE, "rb"))

# ------------------------------------------------------------------
#  B)  call the lattice solver; this takes ~15 s, not 10 minutes
# ------------------------------------------------------------------
S = solve_system_testing.main(
        cmdline=False,
        uid=UID,
        workers=8,           # whatever you like
        bkz_block_size=80,   # or 60/90/100 …
        log_level="INFO")

# ------------------------------------------------------------------
#  C)  verify against the server's third interface
#      (needs the new verify_solution we just fixed)
# ------------------------------------------------------------------
server = LocalServer("FrodoKEM-640-SHAKE", determ=False)        # determ=True if you want fixed keys
kem    = FrodoKEM("FrodoKEM-640-SHAKE")
pk_hex, _, _ = server.call_first_interface(UID)   # gets a fresh pk and stores it in student_files/UID.txt
attack_solver.verify_solution(server, kem, UID, pk_hex, S)