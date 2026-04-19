from pwn import *

r = process(['java', 'VaultDoorTraining'])
r.recvuntil(b'password: ')
r.sendline(b'picoCTF{w4rm1ng_Up_w1tH_jAv4_000HPpgh7Ph}')

r.interactive()