import time
from local_server import LocalServer
from driver import recover_secret_parallel

UID="speed_user"

def test_parallel_speed():
    srv=LocalServer()
    pk,_,_=srv.call_first_interface(UID)
    # baseline single-thread
    t0=time.perf_counter()
    recover_secret_parallel(srv, UID, pk, rows=8, cols=2, workers=1)
    single=time.perf_counter()-t0
    # parallel 4 threads
    t0=time.perf_counter()
    recover_secret_parallel(srv, UID, pk, rows=8, cols=2, workers=4)
    multi=time.perf_counter()-t0
    print(f"single {single:.2f}s vs multi {multi:.2f}s")
    assert multi < single 