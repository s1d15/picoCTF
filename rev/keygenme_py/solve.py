from pwn import *

username_trial = b"BENNETT"

first_part = "picoCTF{1n_7h3_kk3y_of_"
last_part = "}"

flag_len = 32
flag = [''] * flag_len
i = 24
flag[24] = hashlib.sha256(username_trial).hexdigest()[4]
flag[25] = hashlib.sha256(username_trial).hexdigest()[5]
flag[26] = hashlib.sha256(username_trial).hexdigest()[3]
flag[27] = hashlib.sha256(username_trial).hexdigest()[6]
flag[28] = hashlib.sha256(username_trial).hexdigest()[2]
flag[29] = hashlib.sha256(username_trial).hexdigest()[7]
flag[30] = hashlib.sha256(username_trial).hexdigest()[1]
flag[31] = hashlib.sha256(username_trial).hexdigest()[8]

middle_part = ''.join(flag).strip()
print(first_part + middle_part + last_part)