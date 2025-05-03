from frodokem import FrodoKEM
VARIANT = "FrodoKEM-640-SHAKE"
Q = 32768

def matrix_mul(X, Y):
    """Compute matrix multiplication X * Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == nrows_Y, "Mismatched matrix dimensions"
    R = [[0 for j in range(ncols_Y)] for i in range(nrows_X)]
    for i in range(nrows_X):
        for j in range(ncols_Y):
            for k in range(ncols_X):
                R[i][j] += X[i][k] * Y[k][j]
            R[i][j] %= Q
    return R

def matrix_add(X, Y):
    """Compute matrix addition X + Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
    return [[(X[i][j] + Y[i][j]) % Q for j in range(ncols_X)] for i in range(nrows_X)]

def matrix_sub(X, Y):
    """Compute matrix subtraction X - Y mod q"""
    nrows_X = len(X)
    ncols_X = len(X[0])
    nrows_Y = len(Y)
    ncols_Y = len(Y[0])
    assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
    return [[(X[i][j] - Y[i][j]) % Q for j in range(ncols_X)] for i in range(nrows_X)]

def matrix_transpose(X):
    """Compute transpose of matrix X"""
    nrows = len(X)
    ncols = len(X[0])
    return [[X[j][i] for j in range(nrows)] for i in range(ncols)]

class MatrixSet():
    """
    Wrapper class to hold constant matrices
    """
    def __init__(self, n, nbar, seedA=None, b=None):
        if(seedA and b and n == 640 and nbar == 8):
            # FULL SIZE
            kem = FrodoKEM(VARIANT)
            self.A = kem.gen(bytes.fromhex(seedA))
            self.B = kem.unpack(bytes.fromhex(b), n, nbar)
        elif seedA and b:
            # Some other size - currently hardcoded
            self.A = [[(1 if i == j else 0) for j in range(n)] for i in range(n)]
            self.B = [[(1 if i == j else 0) for j in range(nbar)] for i in range(n)]
        else:
            self.A = None
            self.B = None
        self.R = [[(1 if i == j else 1) for j in range(n)] for i in range(nbar)]
        self.E1 = [[(1 if i ==j else 1) for j in range(n)] for i in range(nbar)]
        self.E2 = [[0 for j in range(nbar)] for i in range(nbar)]
        self.K = [[Q//4 for j in range(nbar)] for i in range(nbar)] # q/4 * (8x8 matrix of 1s)




