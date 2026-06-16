from pwn import *
import random
import time

HOST, PORT = 'verbal-sleep.picoctf.net', 60278

def get_random(adj_seed, length):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(adj_seed)  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

found = False
for i in range(200, 1050, 40):
    # r = process(['python3', 'token_generator.py'])
    r = remote(HOST, PORT)

    curr_time = time.time()
    for j in range(50):
        token = get_random(int(curr_time * 1000 + i + j), 20)
        r.sendlineafter('exit):', token)
        print(f'Current offset: {i+j} ms')
        res = r.recvline().strip().decode()
        if 'Sorry' in res:
            continue
        found = True
        print(r.recvline().strip().decode())
        r.close()
        break
    if found:
        break