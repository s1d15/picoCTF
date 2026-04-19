from pwn import *
import ast

# r = process(['python3', 'quantum_scrambler.py'])
HOST, PORT = "verbal-sleep.picoctf.net 55610".split()
r = remote(HOST, PORT)
scrambled = r.recvline().decode().strip()
scrambled = ast.literal_eval(scrambled)
for val in scrambled:
    for v in val:
        if type(v) == list:
            continue
        print(chr(int(v, 16)), end='')
print()

r.interactive()