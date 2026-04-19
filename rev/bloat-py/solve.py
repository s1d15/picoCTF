from pwn import *

r = process(['python3', 'bloat.flag.py'])

a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+ \
            "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "

user_input = a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]

r.recvuntil(b'flag: ')
r.sendline(user_input.encode())
r.recvuntil(b'user:\n')
flag = r.recvline().decode()
print(flag)