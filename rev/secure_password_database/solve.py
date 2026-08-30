from pwn import *

# r = process('./system.out')
HOST, PORT = 'candy-mountain.picoctf.net', 60688
r = remote(HOST, PORT)
r.sendlineafter(b':\r\n', b'')
r.sendlineafter(b'?\r\n', b'89')
r.sendlineafter(b'!\r\n', str(15237662580160011234).encode())
r.interactive()