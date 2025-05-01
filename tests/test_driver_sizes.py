import os
import struct
from driver import recover_secret_parallel, ServerMode, MODE, VARIANT
from local_server import LocalServer

UID_TEST = "pytest_sizes"
OUT_DIR = "attack_outputs"


def _count_ints(path: str) -> int:
    with open(path, "rb") as fh:
        return len(fh.read()) // 2  # 16-bit little-endian ints


def _setup_server_and_pk(uid: str):
    srv = LocalServer()
    srv.check_server()
    pk_hex, _, _ = srv.call_first_interface(uid)
    return srv, pk_hex


def test_demo_size_recovers_correct_dimensions(tmp_path):
    """Run the demo-size attack (8×2) and ensure output matrix has 16 values."""
    server, pk_hex = _setup_server_and_pk(UID_TEST + "_demo")
    S, ss_hex, pt_hex, cipher_hex = recover_secret_parallel(
        server, UID_TEST + "_demo", pk_hex, rows=8, cols=2, workers=2
    )
    assert len(S) == 8 and len(S[0]) == 2, "Demo dimensions wrong"


def test_medium_size_recovers_correct_dimensions(tmp_path):
    """Run a reduced medium-size (16×4) attack and confirm size."""
    server, pk_hex = _setup_server_and_pk(UID_TEST + "_med")
    S, *_ = recover_secret_parallel(
        server, UID_TEST + "_med", pk_hex, rows=16, cols=4, workers=1
    )
    assert len(S) == 16 and len(S[0]) == 4, "Medium dimensions wrong"


def test_quick_full_smoke(tmp_path):
    """A very small slice (4×2) from full to ensure algorithm scales without running whole 3-hour job."""
    server, pk_hex = _setup_server_and_pk(UID_TEST + "_full")
    S, *_ = recover_secret_parallel(
        server, UID_TEST + "_full", pk_hex, rows=4, cols=2, workers=2
    )
    assert len(S) == 4 and len(S[0]) == 2, "Full-size smoke dimensions wrong" 