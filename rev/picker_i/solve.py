from pwn import *

HOST, PORT = "saturn.picoctf.net 50210".split()
r = remote(HOST, PORT)

r.recvuntil(b'> ')
r.sendline(b'win')
hx = r.recvline().decode().split()
for val in hx:
    print(chr(int(val, 16)), end='')
print()
r.interactive()