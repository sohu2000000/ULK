/*
 * linux/arch/i386/kernel/sysenter.c
 *
 * (C) Copyright 2002 Linus Torvalds
 *
 * This file contains the needed initializations to support sysenter.
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/elf.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>

extern asmlinkage void sysenter_entry(void);

/**
 * 在内核初始化期间，系统中每个CPU都调用enable_sep_cpu。
 * 它初始化一些寄存器。(3个系统调用的MSR就初始化了)
 */
void enable_sep_cpu(void *info)
{
	int cpu = get_cpu();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);


	tss->ss1 = __KERNEL_CS;
	tss->esp1 = sizeof(struct tss_struct) + (unsigned long) tss;
	/**
	 * 把内核代码(__KERNEL_CS)的段选择符写入MSR_IA32_SYSENTER_CS
	 */
	wrmsr(MSR_IA32_SYSENTER_CS, __KERNEL_CS, 0);
	/**
	 * tss->esp1中存放的是本地TSS末端地址，将它写入MSR_IA32_SYSENTER_ESP
	 */
	wrmsr(MSR_IA32_SYSENTER_ESP, tss->esp1, 0);
	/**
	 * 把sysenter_entry地址写入到MSR_IA32_SYSENTER_EIP
	 */
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long) sysenter_entry, 0);
	put_cpu();	
}

/*
 * These symbols are defined by vsyscall.o to mark the bounds
 * of the ELF DSO images included therein.
 */
extern const char vsyscall_int80_start, vsyscall_int80_end;
extern const char vsyscall_sysenter_start, vsyscall_sysenter_end;

/*
 * 初始化阶段，sysenter_setup函数建立一个称为vsyscall的页框，其中包括一个小的EFL共享对象(一个很小的ELF动态链接库)。
 * 当进程发出execve()系统调用而开始执行一个EFL程序时，vsyscall页中的代码就会自动被链接到进程的地址空间
 */
static int __init sysenter_setup(void)
{
    /*
     * 为vsyscall页分配一个新页框
	 */
	void *page = (void *)get_zeroed_page(GFP_ATOMIC);

    /*
     * 把新页框的物理地址和FIX_VSYSCALL固定映射的线性地址相关联
	 */
	__set_fixmap(FIX_VSYSCALL, __pa(page), PAGE_READONLY_EXEC);

    /*
     * 将预先定义好的一个或两个EFL共享对象拷贝到该页中
     * 该页面中都包含__kernel_vsyscall()函数，但是实现不同(有的用int,有的用sysenter)
	 */
	if (!boot_cpu_has(X86_FEATURE_SEP)) {
		memcpy(page,
		       &vsyscall_int80_start,
		       &vsyscall_int80_end - &vsyscall_int80_start);
		return 0;
	}

	memcpy(page,
	       &vsyscall_sysenter_start,
	       &vsyscall_sysenter_end - &vsyscall_sysenter_start);

	on_each_cpu(enable_sep_cpu, NULL, 1, 1);
	return 0;
}

__initcall(sysenter_setup);
