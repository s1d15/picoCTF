from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'candy-mountain.picoctf.net', 53942
r = remote(HOST, PORT)

r.recvuntil('flag:\n')
enc = r.recvline().strip().decode()
enc = [enc[i:i+2] for i in range(0, len(enc), 2)]
secret = [83, 51, 67, 114, 51, 116, 0]

for i in range(len(enc)):
    print(chr(int(enc[i], 16) ^ secret[i%6]), end='')
print()