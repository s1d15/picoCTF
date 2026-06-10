from z3 import *
from pwn import *

target = 'kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl'
n = len(target)
s = Solver()

inp = [BitVec(f'c{i}', 32) for i in range(n)]

for i in range(n):
    s.add(inp[i] >= 97, inp[i] <= 122)

s1 = 0x55
s2 = 0x33
s3 = 0xf
fix = 0x61

state = list(inp)

for i in range(3):
    new_state = []
    for j in range(n):
        a = (((j % 0xff) >> 1) & s1) + ((j % 0xff) & s1)
        b = ((a >> 2) & s2) + (s2 & a)
        c = fix + ((((b >> 4) & s3) + state[j] - fix + (s3 & b)) % 0x1a)
        new_state.append(c)
    state = new_state

for i in range(n):
    s.add(state[i] == ord(target[i]))

s.check()
m = s.model()
pw = ''

for i in range(n):
    pw += chr(m[inp[i]].as_long())

HOST, PORT = 'titan.picoctf.net', 60774
r = remote(HOST, PORT)

r.sendline(pw)
r.recvuntil('flag: ')
flag = r.recvline().strip().decode()

print(flag)

r.interactive()