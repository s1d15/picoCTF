import base64

enc =  "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm" + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2" + "JTM0JTVmJTM0JTYyJTYyJTMyJTMyJTM3JTMyJTMx"
flag_bytes = base64.b64decode(enc).decode().split('%')[1:]

flag = ''

for c in flag_bytes:
    flag += chr(int(c, 16))

print('picoCTF{' + flag + '}')