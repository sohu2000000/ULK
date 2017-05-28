/*
 * linux/arch/i386/mm/extable.c
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

#ifdef CONFIG_PNPBIOS
	if (unlikely((regs->xcs & ~15) == (GDT_ENTRY_PNPBIOS_BASE << 3)))
	{
		extern u32 pnp_bios_fault_eip, pnp_bios_fault_esp;
		extern u32 pnp_bios_is_utter_crap;
		pnp_bios_is_utter_crap = 1;
		printk(KERN_CRIT "PNPBIOS fault.. attempting recovery.\n");
		__asm__ volatile(
			"movl %0, %%esp\n\t"
			"jmp *%1\n\t"
			: : "g" (pnp_bios_fault_esp), "g" (pnp_bios_fault_eip));
		panic("do_trap: can't hit this");
	}
#endif

	/*
	 * 查看reg->eip是否是一个系统异常，如reg->eip是系统调用
	 */
	fixup = search_exception_tables(regs->eip);
    /*
     * 如果是异常，将fixup方法赋值给eip从而调用异常的fixup方法
	 * 典型的：fixup_exception可能会向进程发送SIGSEGV信号或者用一个适当的出错码终止系统调用处理程序。
     */
	if (fixup) {
		regs->eip = fixup->fixup;
		return 1;
	}

	return 0;
}
