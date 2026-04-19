from pwn import *

r = process(['./run', 'Hello!'])
r.recvuntil(b': ')
flag = r.recvline().decode().strip()
print(flag)
r.interactive()