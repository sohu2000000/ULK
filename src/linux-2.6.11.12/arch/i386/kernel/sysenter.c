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
 * ���ں˳�ʼ���ڼ䣬ϵͳ��ÿ��CPU������enable_sep_cpu��
 * ����ʼ��һЩ�Ĵ�����(3��ϵͳ���õ�MSR�ͳ�ʼ����)
 */
void enable_sep_cpu(void *info)
{
	int cpu = get_cpu();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);


	tss->ss1 = __KERNEL_CS;
	tss->esp1 = sizeof(struct tss_struct) + (unsigned long) tss;
	/**
	 * ���ں˴���(__KERNEL_CS)�Ķ�ѡ���д��MSR_IA32_SYSENTER_CS
	 */
	wrmsr(MSR_IA32_SYSENTER_CS, __KERNEL_CS, 0);
	/**
	 * tss->esp1�д�ŵ��Ǳ���TSSĩ�˵�ַ������д��MSR_IA32_SYSENTER_ESP
	 */
	wrmsr(MSR_IA32_SYSENTER_ESP, tss->esp1, 0);
	/**
	 * ��sysenter_entry��ַд�뵽MSR_IA32_SYSENTER_EIP
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
 * ��ʼ���׶Σ�sysenter_setup��������һ����Ϊvsyscall��ҳ�����а���һ��С��EFL�������(һ����С��ELF��̬���ӿ�)��
 * �����̷���execve()ϵͳ���ö���ʼִ��һ��EFL����ʱ��vsyscallҳ�еĴ���ͻ��Զ������ӵ����̵ĵ�ַ�ռ�
 */
static int __init sysenter_setup(void)
{
    /*
     * Ϊvsyscallҳ����һ����ҳ��
	 */
	void *page = (void *)get_zeroed_page(GFP_ATOMIC);

    /*
     * ����ҳ��������ַ��FIX_VSYSCALL�̶�ӳ������Ե�ַ�����
	 */
	__set_fixmap(FIX_VSYSCALL, __pa(page), PAGE_READONLY_EXEC);

    /*
     * ��Ԥ�ȶ���õ�һ��������EFL������󿽱�����ҳ��
     * ��ҳ���ж�����__kernel_vsyscall()����������ʵ�ֲ�ͬ(�е���int,�е���sysenter)
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
