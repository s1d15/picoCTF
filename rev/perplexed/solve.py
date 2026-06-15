from z3 import *

bv = [BitVec(f'c{i}', 32) for i in range(27)]
s = Solver()

v3 = bytes.fromhex('617B2375F81EA7E1')[::-1]
v3 += bytes.fromhex('D269DF5B5AFC9DB9')[::-1]
v3 += bytes.fromhex('F467EDF4ED1BFE')[::-1]

v11 = 0
v10 = 0
v7 = 0

for i in range(0x17):
    for j in range(8):
        if v10 == 0:
            v10 = 1
        v6 = 1 << (7 - j)
        v5 = 1 << (7 - v10)
        s.add(((v6 & v3[i]) > 0) == ((v5 & bv[v11]) > 0))
        v10 += 1
        if v10 == 8:
            v10 = 0
            v11 += 1

s.check()
m = s.model()

for i in range(len(bv)):
    print(chr(m[bv[i]].as_long()), end='')