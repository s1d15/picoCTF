from pwn import *

HOST, PORT = 'fickle-tempest.picoctf.net', 54431
r = remote(HOST, PORT)

r.send(process('./solve').recvall())
r.interactive()