from driver import pk_to_secret
from local_server import LocalServer

UID = "pytest_fast"

def test_pk_to_secret_matches_file():
    server = LocalServer()
    # trigger key generation so student_files entry exists
    pk, _, _ = server.call_first_interface(UID)
    derived = pk_to_secret(UID)
    assert derived != ""  # non-empty
    # pull line again for check
    with open(f"student_files/{UID}.txt") as fh:
        file_secret = fh.read().split("True Secret: ")[1].split("\n")[0]
    assert derived == file_secret 