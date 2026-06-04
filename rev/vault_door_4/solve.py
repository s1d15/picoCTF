flag_bytes = [106, 85 , 53 , 116, 95 , 52 , 95 , 98 , 0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f, '0142', '0131', '0164', '063', '0163', '0137', '0145', '060', '2', '1', '3', '8', '7', '2', '1', '3']

flag = ''

for c in flag_bytes:
    if type(c) != str:
        flag += chr(c)
    elif c.startswith('0'):
        flag += chr(int(c, 8))
    else:
        flag += c
print('picoCTF{' + flag + '}')