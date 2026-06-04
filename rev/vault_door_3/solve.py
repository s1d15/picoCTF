enc = 'jU5t_a_sna_3lpm18gb4c_u_4_m2r640'

flag = [''] * 32
flag[:8] = enc[:8]

for i in range(8, 16):
    flag[23-i] = enc[i]

for i in range(16, 32, 2):
    flag[46-i] = enc[i]

for i in range(31, 15, -2):
    flag[i] = enc[i]

print('picoCTF{' + ''.join(flag) + '}')