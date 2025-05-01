import os
import pytest
from frodokem import FrodoKEM
from local_server import LocalServer
import aes_cbc

UID = "pytest_user"

@pytest.fixture(scope="module")
def server():
    return LocalServer()


def test_first_interface(server):
    pk, seedA, b = server.call_first_interface(UID)
    assert len(pk) == 9616 * 2  # hex chars length
    assert len(seedA) == 32
    assert len(b) == (9616 - 16) * 2


def test_second_interface(server):
    kem = FrodoKEM("FrodoKEM-640-SHAKE")
    # Reuse stored values
    with open(os.path.join("student_files", f"{UID}.txt")) as f:
        lines = f.read()
        pk_hex = lines.split("Public Key: ")[1].split("\n")[0]

    ct_bytes, ss_bytes = kem.kem_encaps(bytes.fromhex(pk_hex))
    new_cipher = server.call_second_interface(UID, ct_bytes.hex().upper())
    # returned cipher should contain IV(16)+ct(16) = 32 bytes => 64 hex chars
    assert len(new_cipher)==64


def test_third_interface_wrong_secret(server, capsys):
    # provide wrong secret
    server.call_third_interface(UID, "DEADBEEF")
    captured = capsys.readouterr()
    assert "incorrect" in captured.out.lower() 