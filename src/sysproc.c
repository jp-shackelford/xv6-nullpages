#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

//jps - created mprotect syscall process
//This system call will take an address and remove user
//Write permissions for it and len pages after it
int
sys_mprotect(void)
{
  //Get system call arguments
  char* addr = 0;
  int len;

  if(argptr(0, &addr, sizeof(void*)) < 0)
    return -1;
  if(argint(1, &len) < 0)
    return -1;
  
  //argument checking: len bounds, addr bounds, addr alignmnet
  if(len == 0 || len < 0 || len > myproc()->sz)
    return -1;

  if((uint)addr < 0 || (uint)addr == KERNBASE || (uint)addr > KERNBASE)
    return -1;
	
  if(((unsigned long)addr & 15) != 0)
    return -1;

  //get page table entry and change permissions
  pde_t *pde;
  pte_t *pgtab;
  pte_t *pte;

  pde = &(myproc()->pgdir)[PDX(addr)];
  pgtab = (pte_t*)P2V(PTE_ADDR(*pde));

  // change protection bits for "len" pages
  for(int i = 0; i < len; i++)
  {
    pte = &pgtab[PTX(addr + i)];
    *pte &= ~PTE_W;
  }
  
  //tell the hardware that the page table has changed
  lcr3(V2P(myproc()->pgdir));

  return 0;
}

//jps - created munprotect syscall process
//This system call will take address and grant user
//Write permissions for it and len pages after it
int
sys_munprotect(void)
{
  //Get system call arguments
  char* addr = 0;
  int len;
  
  if(argptr(0, &addr, sizeof(void*)) < 0)
    return -1;
  if(argint(1, &len) < 0)
    return -1;

  //argument checking: len bounds, addr bounds, addr alignmnet
  if(len == 0 || len < 0 || len > myproc()->sz)
    return -1;

  if((uint)addr < 0 || (uint)addr == KERNBASE || (uint)addr > KERNBASE)
    return -1;
	
  if(((unsigned long)addr & 15) != 0)
    return -1;

  //get page table entry and change permissions
  pde_t *pde;
  pte_t *pgtab;
  pte_t *pte;

  pde = &(myproc()->pgdir)[PDX(addr)];
  pgtab = (pte_t*)P2V(PTE_ADDR(*pde));

  for(int i = 0; i < len; i++)
  {
    pte = &pgtab[PTX(addr + i)];
    *pte |= PTE_W;
  }
  
  //tell the hardware that the page table has changed
  lcr3(V2P(myproc()->pgdir));

  return 0;
}
