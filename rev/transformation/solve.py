enc = open('enc', 'r').read()
flag = ['0'] * len(enc) * 2
j = 0
for i in range(0, len(flag), 2):
    flag[i] = chr(ord(enc[j]) >> 8)
    flag[i + 1] = chr(ord(enc[j]) - (ord(flag[i]) << 8)) # flag[i + 1] = chr(ord(enc[j]) & 0xFF)
    j += 1
flag = ''.join(flag)
print(flag)