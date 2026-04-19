from pwn import *

r = process(['python3', 'patchme.flag.py'])
r.recvuntil(b': ')
password = "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"
r.sendline(password.encode())
r.recvuntil(b'user:\n')
flag = r.recvline().decode().strip()
print(flag)