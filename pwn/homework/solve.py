from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'mars.picoctf.net', 31689
r = remote(HOST, PORT)

r.sendline('0!:+::::++++::::++++v')
r.sendline('<00p00g:::+++00g0!:+v'[::-1])
r.sendline('>:+\\p0>>>>>>>>>>>>>>v')
r.sendline('<:00gg,0!+<<<<<<<<<<<'[::-1])

r.interactive()