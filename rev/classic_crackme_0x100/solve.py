from pwn import *

input = ['a'] * 50
output = 'addgdggjdggjgjjmdggjgjjmgjjmjmmpdggjgjjmgjjmjmmpgj'
enc = 'kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl'
offset = [0] * 50

for i in range(50):
    offset[i] = ord(output[i]) - ord(input[i])

pw = ''.join([chr(ord(enc[i]) - offset[i]) for i in range(50)])

HOST, PORT = 'titan.picoctf.net', 60774
r = remote(HOST, PORT)

r.sendline(pw)
r.recvuntil('flag: ')
flag = r.recvline().strip().decode()

print(flag)

r.interactive()