from pwn import *

r = process("./bbbbloat")

r.sendline(str(0x86187).encode())
r.recvuntil(b"? ")
flag = r.recvline().decode().strip()
print(flag)
r.interactive()
