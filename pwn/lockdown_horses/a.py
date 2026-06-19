from pwn import *

context.arch='amd64'

sh = shellcraft.amd64.linux.getdents64(3, 0x100000, 0x1000)
print(sh)