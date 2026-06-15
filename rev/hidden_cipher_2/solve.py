from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'crystal-peak.picoctf.net', 49688
r = remote(HOST, PORT)

r.recvuntil(' is ')
eq = r.recvuntil('?').decode().strip('?')

math_ans = eval(eq)
r.sendline(str(math_ans))
r.recvline()

enc = r.recvline().strip().decode().split(', ')
enc = list(map(int, enc))
for c in enc:
    print(chr(c // math_ans), end='')

r.interactive()