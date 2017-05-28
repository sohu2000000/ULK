/*
 *  linux/arch/i386/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 *
 * I changed all the .align's to 4 (16 byte alignment), as that's faster
 * on a 486.
 *
 * Stack layout in 'ret_from_system_call':
 * 	ptrace needs to have all regs on the stack.
 *	if the order here is changed, it needs to be
 *	updated in fork.c:copy_process, signal.c:do_signal,
 *	ptrace.c and ptrace.h
 *
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *	24(%esp) - orig_eax
 *	28(%esp) - %eip
 *	2C(%esp) - %cs
 *	30(%esp) - %eflags
 *	34(%esp) - %oldesp
 *	38(%esp) - %oldss
 *
 * "current" is in register %ebx during any slow entries.
 */

#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/segment.h>
#include <asm/smp.h>
#include <asm/page.h>
#include "irq_vectors.h"

#define nr_syscalls ((syscall_table_size)/4)

EBX		= 0x00
ECX		= 0x04
EDX		= 0x08
ESI		= 0x0C
EDI		= 0x10
EBP		= 0x14
EAX		= 0x18
DS		= 0x1C
ES		= 0x20
ORIG_EAX	= 0x24
EIP		= 0x28
CS		= 0x2C
EFLAGS		= 0x30
OLDESP		= 0x34
OLDSS		= 0x38

CF_MASK		= 0x00000001
TF_MASK		= 0x00000100
IF_MASK		= 0x00000200
DF_MASK		= 0x00000400 
NT_MASK		= 0x00004000
VM_MASK		= 0x00020000

#ifdef CONFIG_PREEMPT
#define preempt_stop		cli
#else
#define preempt_stop
#define resume_kernel		restore_all //在没有定义CONFIG_PREEMPT的情况下
#endif

/*
 * SAVE_ALL可以在栈中保存中断处理程序可能会使用的所有CPU寄存器
 * 但eflags, cs, eip, ss 及esp除外，因为这些寄存器已经由控制单元自动保存了
 * 然后这个宏把用户数据段的选择符装到ds和es寄存器
 */
/*
 * 相当于把中断发生时,硬件没有保存的寄存器压栈保存下来.把DS.ES设为了__USER_DS是有一定原因的,参考上节所述.
 *
 * 设置为__USER_DS的原因:
 * (检查ds、es、fs及gs段寄存器的内容，如果其中一个寄存器包含的选择符是一个段描述符，并且其DPL值小于CPL，那么，清相关的段寄存器。
 *  控制单元这么做是为了禁止用户态的程序利用内核以前所用的段寄存器。如果不清除这些寄存器的话，恶意的用户程序就会利用他们来访问内核地址空间。
 *  注意到4: 举例说明一下.如果通过系统调用进入内核态.然后将DS,ES的值赋为__KERNEL_DS(在2.4 的内核里),处理完后(调用iret后),
 *           恢复CS,EIP的值,此时CS的CPL是3.因为DS,ES被设为了__KERNEL_DS,所以其DPL是 0,所以要将DS,ES中的值清除.在2.6内核中,发生中断或异常后,
 *           将DS,ES的值设为了__USER_DS,避免了上述的清除过程,提高了效率.)
 */
#define SAVE_ALL \
	cld; \
	pushl %es; \
	pushl %ds; \
	pushl %eax; \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx; \
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es;

#define RESTORE_INT_REGS \
	popl %ebx;	\
	popl %ecx;	\
	popl %edx;	\
	popl %esi;	\
	popl %edi;	\
	popl %ebp;	\
	popl %eax

#define RESTORE_REGS	\
	RESTORE_INT_REGS; \
1:	popl %ds;	\
2:	popl %es;	\
.section .fixup,"ax";	\
3:	movl $0,(%esp);	\
	jmp 1b;		\
4:	movl $0,(%esp);	\
	jmp 2b;		\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,3b;	\
	.long 2b,4b;	\
.previous

#define RESTORE_ALL	\
	RESTORE_REGS	\ //pop在SAVE_ALL中入栈的寄存器
	addl $4, %esp;	\  //记否?在SAVE_ALL之前压入了一个中断向量的负值或者是系统调用号
1:	iret;		\ //iret中断返回,交给硬件完成中断的返回工作
.section .fixup,"ax";   \
2:	sti;		\
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es; \
	movl $11,%eax;	\
	call do_exit;	\
.previous;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 1b,2b;	\
.previous


ENTRY(ret_from_fork)
	pushl %eax
	call schedule_tail
	GET_THREAD_INFO(%ebp)
	popl %eax
	jmp syscall_exit

/*
 * Return to user mode is not as complex as all this looks,
 * but we want the default path for a system call return to
 * go as quickly as possible which is why some of this is
 * less clear than it otherwise should be.
 */

	# userspace resumption stub bypassing syscall exit tracing
	ALIGN

/*异常返回分析: 异常返回的后半部份与IRQ中断返回相比只是多了一个preempt_stop的处理.*/
ret_from_exception:
	/**
	 * 在中断返回前，handle_IRQ_event调用local_irq_disable禁止了中断
	 * 所以在中断返回时，不用关中断，但是在异常返回时，需要将中断关闭。
	 */
	preempt_stop

/*IRQ中断返回分析*/
ret_from_intr:
	/**
	 * 把当前thread_info半截到ebp中。
	 */
	GET_THREAD_INFO(%ebp) //取得当前过程的task描述符
	/**
	 * 接下来判断EFLAGS和CS，确定是否运行在用户态，是否是VM模式。
	 */
	movl EFLAGS(%esp), %eax		# mix EFLAGS and CS //中断前的EFLAGS中的值存进EAX
	movb CS(%esp), %al	//将中断前的CS低16移至AL
	//#至此EFLAGS 的H16和CS的L16构成了EAX的内容
	
	testl $(VM_MASK | 3), %eax //EFLAGS中有一位表示是否运行在vm86模式中,CS的最低二位表示当前进程的运行级别
	/**
	 * 如果是运行在内核态，并且不是VM模式，就跳到resume_kernel，
	 * 否则跳转到resume_userspace
	 */
	jz resume_kernel		# returning to kernel or vm86-space // 如果中断前不是在用户空间,且不是在VM86模式下,跳转到resume_kernel

/**
 * 恢复用户态程序的流程入口。
 */
ENTRY(resume_userspace)
	/**
	 * 不清楚为什么还要禁用中断
	 */
	//开中断,以防中断丢失  
	// TODO: cli不是关中断么?
 	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	/**
	 * 检查thread_info的flag
	 */
	movl TI_flags(%ebp), %ecx //将task->flags成员的值存进ecx 
	/**
	 * 如果设置了_TIF_WORK_MASK中任何一位，就表示有等待处理的事情
	 * 跳到work_pending处理这些挂起的事件。
	 * 否则调用restore_all回到用户态。
	 */
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done on
					# int/exception return? //还有事情没做完?
	jne work_pending //还有事情没做完?
	jmp restore_all //所有事情都处理完了

#ifdef CONFIG_PREEMPT

/**
 * 当从异常或者中断返回时，需要返回到内核，则跳转到此处。
 */
//如果编译内核被配置成允许被抢占的情况下的resume_kernel
ENTRY(resume_kernel)
	/**
	 * 不知道此处为何需要再加cli,如果是从中断或者异常跳转到这里，那么已经是关中断状态了。
	 * 也许是还有其他地方跳到这里吧。
	 */
	cli
	/**
	 * 首先判断内核是否允许抢占，请请记住ebp中保存的是thread_info
	 */
	cmpl $0,TI_preempt_count(%ebp)	# non-zero preempt_count ?
	/**
	 * 当前不允许抢占，就继续执行内核代码。进入restore_all恢复原来进程
	 */
	jnz restore_all //preempt_count为非0，表示此时不能发生抢占，则跳转到restore_all
	/**
	 * 否则抢占计数为0，就判断是否有调度需求。
	 */
need_resched:
	movl TI_flags(%ebp), %ecx	# need_resched set ?
	/**
	 * 判断是否有调度需求。
	 */
	testb $_TIF_NEED_RESCHED, %cl //此时preempt_count=0,如果need_resched标志置位，则发生调度。反之则跳转到restore_all
	/**
	 * 不需要调度，就继续执行内核代码。进入restore_all恢复原来进程
	 */
	jz restore_all
	/**
	 * 虽然有调度需求，但是当前是关中断状态，显然，这是不合理的。
	 * 这时回到用户态做什么呢？timer中断都可能被关了。系统怎么工作？
	 * 如果正在被恢复的内核控制路径是在禁用本地CPU中断的情况运行，那么也跳转到restore_all恢复原来进程
	 * 在这种情况下，进程切换可能破坏内核数据结构
	 */
	testl $IF_MASK,EFLAGS(%esp)     # interrupts off (exception path) ? //如果是发生了异常，则不会进行抢占调度，此时preempt_count=0，且need_resched置位
	jz restore_all
	/**
	 * 如果需要进程进程切换，就调用
	 * preempt_schedule_irq会设置PREEMPT_ACTIVE标志，并把大内核锁暂时设置为-1。然后开中断并调用schedule。
	 */
	call preempt_schedule_irq 
	jmp need_resched //跳转到need_resched，判断是否又需要发生被调度
#endif

/* SYSENTER_RETURN points to after the "sysenter" instruction in
   the vsyscall page.  See vsyscall-sysentry.S, which defines the symbol.  */

	# sysenter call handler stub
/*
 * 调用sysenter_entry之前会:
 * 1. 标准库中的封装例程把系统调用号装入eax寄存器，并调用__kernel_vsyscall()函数
 * 2. 函数__kernel_vsyscall()把ebp、edx和ecx的内容保存到用户态堆栈中，把用户态指针拷贝到ebp中，然后执行sysenter指令
 * 3. CPU从用户态切换到内核态，内核开始执行sysenter_entry()函数(由SYSENTER_EIP_MSR寄存器指向)
 * 函数地址保存在SYSENTER_EIP_MSR中，CPU从用户态切换到内核态，内核开始执行这个函数
 */
ENTRY(sysenter_entry)
    /*
     * 建立内核堆栈指针，把esp0的内容装入esp，esp0字段总是存放当前进程的内核堆栈指针
	 */
	movl TSS_sysenter_esp0(%esp),%esp
sysenter_past_esp:
    /*
     * 打开本地中断
	 */
	sti
	/*
	 * 把用户数据段的段选择符、当前用户栈指针、eflags寄存器、用户代码段的段选择符
	 * 以及从系统调用退出时要执行的指令的地址保存到内核堆栈中
	 */
	pushl $(__USER_DS)
	pushl %ebp
	pushfl
	pushl $(__USER_CS)
	pushl $SYSENTER_RETURN

/*
 * Load the potential sixth argument from user stack.
 * Careful about security.
 */
	cmpl $__PAGE_OFFSET-3,%ebp
	jae syscall_fault
	/*
	 * 把原来由封装例程传递的寄存器的值恢复到ebp中
	 */
1:	movl (%ebp),%ebp
    /*
     * 通过执行一系列指令调用系统调用处理程序，同system_call标记处开始的指令流程
	 */
.section __ex_table,"a"
	.align 4
	.long 1b,syscall_fault
.previous

	pushl %eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)

	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
	call *sys_call_table(,%eax,4)

	/*
	 * 系统调用服务例程结束后，从eax获得系统调用服务例程的返回码，
	 * 并将返回码存入内核栈中保存用户态eax寄存器值的位置
	 */
	movl %eax,EAX(%esp)
	/*
	 * 禁止本地中断，并检查current的thread_info结构中的标准
	 */
	cli
	movl TI_flags(%ebp), %ecx
	/*
	 * 如果有任何标志被设置，那么在返回到用户态之前还需要完成一些工作，跳转到syscall_exit_work
	 * 最后执行iret汇编指令从内核态堆栈中去取5个参数。这样，CPU切换到用户态并开始执行SYSENTER_RETURN标记处的代码
	 */
	testw $_TIF_ALLWORK_MASK, %cx
	jne syscall_exit_work
/* if something modifies registers it must also disable sysexit */
	/*
	 * 如果标志都被清零，就会很快返回到用户态。
	 * 将先前保存的一对堆栈值加载到edx和ecx中，edx获得SYSENTER_RETURN标志处的地址，而ecx获得当前用户数据栈的指针
	 */
	movl EIP(%esp), %edx
	movl OLDESP(%esp), %ecx
	xorl %ebp,%ebp
	/*
	 * 恢复中断
	 */
	sti
	/*
	 * 执行sysexit
	 * sysexit是和sysenter配对的汇编语言指令:他允许从内核态快速切换到用户态
	 * 1. 把SYSENTER_CS_MSR(内核代码的段选择符)寄存器的值加16所得到的结果加载到cs寄存器(加载的是用户态代码的段选择符)
	 * 2. 把edx寄存器的内容拷贝到eip寄存器
	 * 3. 把SYSENTER_CS_MSR寄存器的值加24所得到的值加载到SS寄存器(加载的是用户态数据段的段选择符)
	 * 4. 把ecx寄存器的内容拷贝到esp寄存器
	 * 5. CPU从内核态切换到用户态，并开始执行其地址存放在edx中的那条指令
	 */
	sysexit


	# system call handler stub

/*
 * system_call 首先把系统调用号和这个异常处理程序可以用到的所有CPU寄存器保存到相应的栈中
 * 不包括由控制单元已自动保存的eflags、cs、eip、ss和esp寄存器。使用的是SAVE_ALL宏。
 * 这个宏也在ds和es中装入内核数据段的段选择符
 * 
 */
/*系统调用入口*/
ENTRY(system_call)
	pushl %eax			# save orig_eax /*save orig_eax(系统调用号).在发生系统调用的时候,系统调用号都是存放在EAX中的*/
	SAVE_ALL
	/*
	 * 随后，在ebx中存放当前进程的thread_info数据结构的地址，这是通过获得内核栈指针的值并把它取整得到4KB或8KB的倍数完成的
	 */
	GET_THREAD_INFO(%ebp)
					# system call tracing in operation //取得当前进程的task描述符
	/*
	 * 检查thread_info的flags字段的_TIF_SYSCALL_TRACE和_TIF_SYSCALL_AUDIT标识之一是否被设置为1，
	 * 也就是检查是否有某一调试程序正在跟踪执行程序对系统调用的调用，
	 * 如果是这种情况，那么两次调用do_syscall_trace函数: 、
	 * 一次正好在这个系统调用服务例程执行之前，一次在其后，
	 * 这个函数停止current，并因此允许调试进程收集关于current的信息
	 */
	/*如果进程被TRACE,跳转至syscall_trace_entry,假设进程没有被trace*/
	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry 
	/*
	 * 对用户态进程传递来的系统调用号进行有效性检查。
	 * 如果大于或者等于系统调用分派表中的表项数，系统调用处理程序就终止
	 */	
	cmpl $(nr_syscalls), %eax //在系统调用表中取得相应的处理函数
	jae syscall_badsys //系统调用号无效
syscall_call:
    /*
     * 调用与eax中所包含的系统调用号对应的特定服务例程
     * 因为分派表中的每个表项占4个字节，因此首先把系统调用号乘以4，再加上sys_call_table分派表的起始地址
     * 然后从这个地址单元获取指向服务例程的指针，内核就找到了要调用的服务例程
	 */
	call *sys_call_table(,%eax,4) //call相应的处理函数
    /*
     * 当系统调用服务例程结束时，system_call函数从eax获得它的返回值，
     * 并把这个返回值存放在曾经爆出用户态eax寄存器的那个栈单元位置上
	 */	
	movl %eax,EAX(%esp)		# store the return value //将返回值压入调用前的EAX中
/*系统调用返回分析*/
syscall_exit:
    /*
     * 关闭本地中断并检查当前进程的thread_info结构中的标志
	 */
	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	movl TI_flags(%ebp), %ecx
	/*
	 * 0xffff与标志位想与，如果所有的标志位都没有被设置，函数就跳转到retore all
	 * 只要有一个标志被设置，那么就要在返回用户态之前完成一些工作
	 */
	testw $_TIF_ALLWORK_MASK, %cx	# current->work
	jne syscall_exit_work

//restore_all被定义成RESTRORE_ALL
restore_all:
    /*
     * 恢复保存在内核栈中的寄存器的值，并执行iret汇编指令以重新开始用户态的执行
	 */
	RESTORE_ALL

	# perform work that needs to be done immediately before resumption
	ALIGN

/**
 * 在回到用户态前，如果有挂起的任务，就处理这些挂起的任务。
 */
work_pending:
	/**
	 * 检查是否需要重新调度。
	 */
	testb $_TIF_NEED_RESCHED, %cl //在返回用户空间时，只需要判断need_resched是否置位，不需要判断preempt_count(用户空间)，如果置位则发生调度，反之则跳转到work_notifysig
	/**
	 * 不需要重新调度，需要回到用户态，在回到用户态前，先检查待处理的信号，进入work_notifysig片段
	 */
	jz work_notifysig
/**
 * 否则，有调度需要，处理调度。
 */
work_resched:
	/**
	 * 调度一下。可能没有调出去，也可能出去后又调度回来了。
	 */
	call schedule
	/**
	 * 因为可能是调度出去后，又回来了，所以需要重新关中断。
	 */
	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	/**
	 * 这个处理流程是否有点眼熟呢？？
	 */
	/*
	 * 再次进行检查，如果只设置了TIF_SYSCALL_TRACE, TIF_SYSCALL_AUDIT, 或 TIF_SINGLESTEP，就是说没等待要处理的事件了，调用restore_all回到用户态。
	 */
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done other
					# than syscall tracing?
	jz restore_all
	/*
	 * 如果检查到还需要调度，就回到work_resched
	 */
	testb $_TIF_NEED_RESCHED, %cl
	jnz work_resched //如果need_resched再次被置位，则继续调度，反之，则执行work_notifysig

/**
 * 好了，运行到这里，说明没有重新调度的要求。
 * 或者说有调度要求，但是调度出动后，又回来了。
 * 总之，现在是没有调度要求了。在回到用户态前，处理信号。
 * 需要注意的是：这个入口有不止从一个地方进入。
 * 一是从上面两句转入，二是从更上面的jmp跳入。
 * 接下来有两个事件需要处理：一是信号，二是VM86模式。
 * 其中VM86模式我们不太关心。信号呢，很复杂的流程，至少需要一章才说清楚。也略过。
 */
work_notifysig:				# deal with pending signals and
					# notify-resume requests
	/*
	 * 如果用户态程序的eflags寄存器的VM控制标志被设置了，就进入work_notifysig_v86
	 */
	testl $VM_MASK, EFLAGS(%esp) #VM模式?
	movl %esp, %eax
	jne work_notifysig_v86		# returning to kernel-space or
					# vm86-space
	xorl %edx, %edx
	call do_notify_resume //进行信号处理
	jmp restore_all

	ALIGN
work_notifysig_v86:
	pushl %ecx			# save ti_flags for do_notify_resume
	/*
	 * 调用save_v86_state函数在用户态地址空间建立虚拟8086模式的数据结构
	 */
	call save_v86_state		# %eax contains pt_regs pointer
	popl %ecx
	movl %eax, %esp
	xorl %edx, %edx
	/*
	 * 调用do_notify_resume处理挂起的信号和单步执行
	 */
	call do_notify_resume
	/*
	 * 跳转到restore_all片段，恢复被中断的程序
	 */
	jmp restore_all

	# perform syscall exit tracing
	ALIGN
syscall_trace_entry:
	movl $-ENOSYS,EAX(%esp)
	movl %esp, %eax
	xorl %edx,%edx
	call do_syscall_trace
	movl ORIG_EAX(%esp), %eax
	cmpl $(nr_syscalls), %eax
	jnae syscall_call
	jmp syscall_exit

	# perform syscall exit tracing
	ALIGN

syscall_exit_work:
    /*
     * 如果_TIF_SYSCALL_TRACE标志被设置，system_call函数就第二次调用do_syscall_trace()
     * 然后跳转到resume_userspace
     * 如果_TIF_SYSCALL_TRACE没有设置，跳转到work_pending
     * 在resume_userspace和work_pending处的代码检查重新调度请求、虚拟8086模式，挂起信号和单步执行
     * 最终跳转到restore all标记处以恢复用户态进程的执行
	 */
	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP), %cl
	jz work_pending
	sti				# could let do_syscall_trace() call
					# schedule() instead
	movl %esp, %eax
	movl $1, %edx
	call do_syscall_trace
	jmp resume_userspace

	ALIGN
syscall_fault:
	pushl %eax			# save orig_eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
	movl $-EFAULT,EAX(%esp)
	jmp resume_userspace

	ALIGN
syscall_badsys:
    /*
     * 如果系统调用号无效，该函数就把-ENOSYS值存放在曾保存eax寄存器的单元中
     * 然后跳到resume_userspace，这样当进程恢复他在用户态的执行时，会在eax中发现一个负的返回码
	 */
	movl $-ENOSYS,EAX(%esp)
	jmp resume_userspace

/*
 * Build the entry stubs and pointer table with
 * some assembler magic.
 */
.data

/*interrupt数组定义*/
ENTRY(interrupt)
.text


vector=0
ENTRY(irq_entries_start)
.rept NR_IRQS
	ALIGN
/*
 * 把中断号减去256的结果保存在栈中，内核用负数表示所有的中断，因为正数表示系统调用，
 * 当引用这个数的时候，可以对所有的中断处理程序都执行相同的代码，这段通用代码开始于标签common_interrupt
 */	
/*
 * 相当于,interrupt[i]执行下列操作:
 * Pushl $i-256	  //中断号取负再压栈
 * Jmp common_interrupt		 //跳转至一段公共的处理函数
 */
1:	pushl $vector-256
	jmp common_interrupt
.data
	.long 1b
.text
vector=vector+1
.endr

	ALIGN

/*IRQ入口,中断入口*/
common_interrupt:
	/*common_interrupt 首先调用 SAVE ALL保存寄存器*/
	SAVE_ALL
	
	/*寄存器保存后，栈顶的地址被存放到eax寄存器里面*/
	movl %esp,%eax
	/*
	 * 调用do_IRQ()函数,
	 * 调用相应的中断处理函数
	 */
	call do_IRQ
	/* 
	 * 执行do_IRQ的ret指令的时候，控制转移到ret_from_intr()函数
	 * 从中断返回
	 */
	jmp ret_from_intr

/**
 * 处理器间的中断处理程序的汇编语言代码是由BUILD_INTERRUPT宏产生的。
 * 它保存寄存器，从栈顶压入向量号减256的值，然后调用高级C函数（其名字就是低级处理程序的名字加前缀smp_）。
 * 如，CALL_FUNCTION_VECTOR类型的处理器间中断的低级处理程序是call_function_interrupt，它调用smp_call_function_interrupt的高级处理程序。
 */
#define BUILD_INTERRUPT(name, nr)	\
ENTRY(name)				\
	pushl $nr-256;			\
	SAVE_ALL			\
	movl %esp,%eax;			\
	call smp_/**/name;		\
	jmp ret_from_intr;

/* The include is where all of the SMP etc. interrupts come from */
#include "entry_arch.h"

/**
 * 故障-0
 * 当一个程序试图执行整数被0除操作时产生。
 */
ENTRY(divide_error)
	pushl $0			# no error code
	pushl $do_divide_error
	ALIGN

/*注意这里的movl是 movl %1, %2， 将1中的内容放入2中，因为用了cld*/
error_code:
	/**
	 * 保存高级C函数会用到的寄存器到栈中，请参见高级C函数的
	 */
	pushl %ds
	pushl %eax
	xorl %eax, %eax //EAX中的值变为零
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	decl %eax			# eax = -1
	pushl %ecx
	pushl %ebx
	
	/**
	 * cld指令清eflags方向标志DF，主要用于movs这样的指令。
	 */
	cld
	movl %es, %ecx
	/**
	 * 将esp+32处的高级C函数地址载入edi.也就是异常处理函数的地址如do_page_fault
	 * 但是为什么在ESP+32这个地方呢?
	 */
	movl ES(%esp), %edi		# get the function address
	/**
	 * 将esp+36处的出错码复制到edx中，将将-1写到栈中。
	 * 请注意前面xorl %eax, %eax和decl %eax一句，它将eax中置-1
	 * 这样，如果是异常，这个位置就是-1，否则就表示是0x80系统调用。
	 */
	movl ORIG_EAX(%esp), %edx	# get the error code
	movl %eax, ORIG_EAX(%esp)
	movl %ecx, ES(%esp)
	
	/**
	 * 把用户数据段选择符复制以ds和es寄存器中。
	 */
	movl $(__USER_DS), %ecx
	movl %ecx, %ds
	movl %ecx, %es
	
	/**
	 * 把内核栈的当前栈顶复制到eax。这是一个内存单元的地址。
	 * 它的地址是最后被pushl到栈中的值的地址。通过这个地址就可以访问所有保存的寄存器了。
	 * 也就是pt_regs结构。
	 */
	movl %esp,%eax			# pt_regs pointer

	/*
	 * 到此为止,以上就为中断处理跟异常处理构造了一个统一的堆栈,当然这样做只是为了使用统一的参数类型,即struct pt_regs
	 */
	
	/**
	 * 调用高级C函数，被调用函数的参数是通过eax和edx传递。也就是调用异常处理函数
	 * 请参见fastcall void do_page_fault(struct pt_regs *regs, unsigned long error_code)
	 * 其中的fastcall表示由寄存器传参，regs的值在eax，error_code的值在edx中。
	 */
	//调用相应的异常处理函数
	call *%edi
	jmp ret_from_exception

/*16号异常处理入口分析，异常处理程序也有很多相同的操作，另外可看page_fault*/
ENTRY(coprocessor_error)
	pushl $0 /*把0入栈.如果异常没有产生一个硬件出错码,就把0入栈*/
	pushl $do_coprocessor_error /*入栈，相应的异常处理程序*/
	jmp error_code /*跳转到error_code*/

ENTRY(simd_coprocessor_error)
	pushl $0
	pushl $do_simd_coprocessor_error
	jmp error_code

/**
 * 故障-7
 * cr0的TS标志被设置，ESCAPE、MMX或者XMM指令被执行
 */
ENTRY(device_not_available)
	pushl $-1			# mark this as an int
	SAVE_ALL
	movl %cr0, %eax
	testl $0x4, %eax		# EM (math emulation bit)
	jne device_not_available_emulate
	preempt_stop
	call math_state_restore
	jmp ret_from_exception
device_not_available_emulate:
	pushl $0			# temporary storage for ORIG_EIP
	call math_emulate
	addl $4, %esp
	jmp ret_from_exception

/*
 * Debug traps and NMI can happen at the one SYSENTER instruction
 * that sets up the real kernel stack. Check here, since we can't
 * allow the wrong stack to be used.
 *
 * "TSS_sysenter_esp0+12" is because the NMI/debug handler will have
 * already pushed 3 words if it hits on the sysenter instruction:
 * eflags, cs and eip.
 *
 * We just load the right stack, and push the three (known) values
 * by hand onto the new stack - while updating the return eip past
 * the instruction that would have done it for sysenter.
 */
#define FIX_STACK(offset, ok, label)		\
	cmpw $__KERNEL_CS,4(%esp);		\
	jne ok;					\
label:						\
	movl TSS_sysenter_esp0+offset(%esp),%esp;	\
	pushfl;					\
	pushl $__KERNEL_CS;			\
	pushl $sysenter_past_esp

/**
 * 陷阱或故障-1
 * 产生于：设置eflags的TF标志时，或当一条指令或者操作数的地址落在一个活动DEBUG寄存器的范围之内。
 */
ENTRY(debug)
	cmpl $sysenter_entry,(%esp)
	jne debug_stack_correct
	FIX_STACK(12, debug_stack_correct, debug_esp_fix_insn)
debug_stack_correct:
	pushl $-1			# mark this as an int
	SAVE_ALL
	xorl %edx,%edx			# error code 0
	movl %esp,%eax			# pt_regs pointer
	call do_debug
	testl %eax,%eax
	jnz restore_all
	jmp ret_from_exception

/*
 * NMI is doubly nasty. It can happen _while_ we're handling
 * a debug fault, and the debug fault hasn't yet been able to
 * clear up the stack. So we first check whether we got  an
 * NMI on the sysenter entry path, but after that we need to
 * check whether we got an NMI on the debug path where the debug
 * fault happened on the sysenter path.
 */
/**
 * 未用-2
 * 为非屏蔽中断保留(利用NMI引脚的中断)
 */
ENTRY(nmi)
	cmpl $sysenter_entry,(%esp)
	je nmi_stack_fixup
	pushl %eax
	movl %esp,%eax
	/* Do not access memory above the end of our stack page,
	 * it might not exist.
	 */
	andl $(THREAD_SIZE-1),%eax
	cmpl $(THREAD_SIZE-20),%eax
	popl %eax
	jae nmi_stack_correct
	cmpl $sysenter_entry,12(%esp)
	je nmi_debug_stack_check
nmi_stack_correct:
	pushl %eax
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_nmi
	RESTORE_ALL

nmi_stack_fixup:
	FIX_STACK(12,nmi_stack_correct, 1)
	jmp nmi_stack_correct
nmi_debug_stack_check:
	cmpw $__KERNEL_CS,16(%esp)
	jne nmi_stack_correct
	cmpl $debug - 1,(%esp)
	jle nmi_stack_correct
	cmpl $debug_esp_fix_insn,(%esp)
	jle nmi_debug_stack_fixup
nmi_debug_stack_fixup:
	FIX_STACK(24,nmi_stack_correct, 1)
	jmp nmi_stack_correct

/**
 * 陷阱-0
 * 由int3断点指令(通常由debugger插入)引起
 */
ENTRY(int3)
	pushl $-1			# mark this as an int
	SAVE_ALL
	xorl %edx,%edx		# zero error code
	movl %esp,%eax		# pt_regs pointer
	call do_int3
	testl %eax,%eax
	jnz restore_all
	jmp ret_from_exception

/**
 * 陷阱-4
 * 当eflags的OF(overflow)标志被设置时，into(检查溢出)指令被执行
 */
ENTRY(overflow)
	pushl $0
	pushl $do_overflow
	jmp error_code

/**
 * 故障-5
 * 对于有效范围之外的操作数，bound(检查地址边界)指令被执行
 */
ENTRY(bounds)
	pushl $0
	pushl $do_bounds
	jmp error_code

/**
 * 故障-6
 * CPU执行单元检测到一个无效的操作码。
 */
ENTRY(invalid_op)
	pushl $0
	pushl $do_invalid_op
	jmp error_code

/**
 * 异常中止-9
 * 因外部的数学协处理器引起的问题（仅适用于80386）
 */
ENTRY(coprocessor_segment_overrun)
	pushl $0
	pushl $do_coprocessor_segment_overrun
	jmp error_code

/**
 * 故障-10
 * CPU试图让一个上下文切换到无效的TSS进程。
 */
ENTRY(invalid_TSS)
	pushl $do_invalid_TSS
	jmp error_code

/**
 * 故障-11
 * 引用一个不存在的内存段（段描述符的Segment-Present标志被清0）
 */
ENTRY(segment_not_present)
	pushl $do_segment_not_present
	jmp error_code

/**
 * 故障-12
 * 试图超过栈段界限的指令。或者由SS标识的段不在内存。
 */
ENTRY(stack_segment)
	pushl $do_stack_segment
	jmp error_code

/**
 * 故障-13
 * 违反了保护模式下的保护规则之一。
 */
ENTRY(general_protection)
	pushl $do_general_protection
	jmp error_code

/**
 * 操作数的地址没有被正确的对齐（例如，一个长整数的地址不是4的倍数）
 */
ENTRY(alignment_check)
	pushl $do_alignment_check
	jmp error_code

/**
 * 故障-14
 * 寻址的页不在内存，相应的页表项为空。或者违反了一种分页保护机制。
 */
ENTRY(page_fault)
	pushl $do_page_fault
	jmp error_code

#ifdef CONFIG_X86_MCE
/**
 * 异常中止-18
 * 机器检查机制检测到一个CPU错误或者总线错误
 */
ENTRY(machine_check)
	pushl $0
	pushl machine_check_vector
	jmp error_code
#endif

ENTRY(spurious_interrupt_bug)
	pushl $0
	pushl $do_spurious_interrupt_bug
	jmp error_code

.data
/*　
 * 为了把系统调用号和相应的服务例程关联起来，内核利用了一个系统调用分派表(dispatch table)。
 * 这个表存放在sys_call_table数组中
 */
ENTRY(sys_call_table)
	.long sys_restart_syscall	/* 0 - old "setup()" system call, used for restarting */
	.long sys_exit
	.long sys_fork
	.long sys_read
	.long sys_write
	.long sys_open		/* 5 */
	.long sys_close
	.long sys_waitpid
	.long sys_creat
	.long sys_link
	.long sys_unlink	/* 10 */
	.long sys_execve
	.long sys_chdir
	.long sys_time
	.long sys_mknod
	.long sys_chmod		/* 15 */
	.long sys_lchown16
	.long sys_ni_syscall	/* old break syscall holder */
	.long sys_stat
	.long sys_lseek
	.long sys_getpid	/* 20 */
	.long sys_mount
	.long sys_oldumount
	.long sys_setuid16
	.long sys_getuid16
	.long sys_stime		/* 25 */
	.long sys_ptrace
	.long sys_alarm
	.long sys_fstat
	.long sys_pause
	.long sys_utime		/* 30 */
	.long sys_ni_syscall	/* old stty syscall holder */
	.long sys_ni_syscall	/* old gtty syscall holder */
	.long sys_access
	.long sys_nice
	.long sys_ni_syscall	/* 35 - old ftime syscall holder */
	.long sys_sync
	.long sys_kill
	.long sys_rename
	.long sys_mkdir
	.long sys_rmdir		/* 40 */
	.long sys_dup
	.long sys_pipe
	.long sys_times
	.long sys_ni_syscall	/* old prof syscall holder */
	.long sys_brk		/* 45 */
	.long sys_setgid16
	.long sys_getgid16
	.long sys_signal
	.long sys_geteuid16
	.long sys_getegid16	/* 50 */
	.long sys_acct
	.long sys_umount	/* recycled never used phys() */
	.long sys_ni_syscall	/* old lock syscall holder */
	.long sys_ioctl
	.long sys_fcntl		/* 55 */
	.long sys_ni_syscall	/* old mpx syscall holder */
	.long sys_setpgid
	.long sys_ni_syscall	/* old ulimit syscall holder */
	.long sys_olduname
	.long sys_umask		/* 60 */
	.long sys_chroot
	.long sys_ustat
	.long sys_dup2
	.long sys_getppid
	.long sys_getpgrp	/* 65 */
	.long sys_setsid
	.long sys_sigaction
	.long sys_sgetmask
	.long sys_ssetmask
	.long sys_setreuid16	/* 70 */
	.long sys_setregid16
	.long sys_sigsuspend
	.long sys_sigpending
	.long sys_sethostname
	.long sys_setrlimit	/* 75 */
	.long sys_old_getrlimit
	.long sys_getrusage
	.long sys_gettimeofday
	.long sys_settimeofday
	.long sys_getgroups16	/* 80 */
	.long sys_setgroups16
	.long old_select
	.long sys_symlink
	.long sys_lstat
	.long sys_readlink	/* 85 */
	.long sys_uselib
	.long sys_swapon
	.long sys_reboot
	.long old_readdir
	.long old_mmap		/* 90 */
	.long sys_munmap
	.long sys_truncate
	.long sys_ftruncate
	.long sys_fchmod
	.long sys_fchown16	/* 95 */
	.long sys_getpriority
	.long sys_setpriority
	.long sys_ni_syscall	/* old profil syscall holder */
	.long sys_statfs
	.long sys_fstatfs	/* 100 */
	.long sys_ioperm
	.long sys_socketcall
	.long sys_syslog
	.long sys_setitimer
	.long sys_getitimer	/* 105 */
	.long sys_newstat
	.long sys_newlstat
	.long sys_newfstat
	.long sys_uname
	.long sys_iopl		/* 110 */
	.long sys_vhangup
	.long sys_ni_syscall	/* old "idle" system call */
	.long sys_vm86old
	.long sys_wait4
	.long sys_swapoff	/* 115 */
	.long sys_sysinfo
	.long sys_ipc
	.long sys_fsync
	.long sys_sigreturn
	.long sys_clone		/* 120 */
	.long sys_setdomainname
	.long sys_newuname
	.long sys_modify_ldt
	.long sys_adjtimex
	.long sys_mprotect	/* 125 */
	.long sys_sigprocmask
	.long sys_ni_syscall	/* old "create_module" */ 
	.long sys_init_module
	.long sys_delete_module
	.long sys_ni_syscall	/* 130:	old "get_kernel_syms" */
	.long sys_quotactl
	.long sys_getpgid
	.long sys_fchdir
	.long sys_bdflush
	.long sys_sysfs		/* 135 */
	.long sys_personality
	.long sys_ni_syscall	/* reserved for afs_syscall */
	.long sys_setfsuid16
	.long sys_setfsgid16
	.long sys_llseek	/* 140 */
	.long sys_getdents
	.long sys_select
	.long sys_flock
	.long sys_msync
	.long sys_readv		/* 145 */
	.long sys_writev
	.long sys_getsid
	.long sys_fdatasync
	.long sys_sysctl
	.long sys_mlock		/* 150 */
	.long sys_munlock
	.long sys_mlockall
	.long sys_munlockall
	.long sys_sched_setparam
	.long sys_sched_getparam   /* 155 */
	.long sys_sched_setscheduler
	.long sys_sched_getscheduler
	.long sys_sched_yield
	.long sys_sched_get_priority_max
	.long sys_sched_get_priority_min  /* 160 */
	.long sys_sched_rr_get_interval
	.long sys_nanosleep
	.long sys_mremap
	.long sys_setresuid16
	.long sys_getresuid16	/* 165 */
	.long sys_vm86
	.long sys_ni_syscall	/* Old sys_query_module */
	.long sys_poll
	.long sys_nfsservctl
	.long sys_setresgid16	/* 170 */
	.long sys_getresgid16
	.long sys_prctl
	.long sys_rt_sigreturn
	.long sys_rt_sigaction
	.long sys_rt_sigprocmask	/* 175 */
	.long sys_rt_sigpending
	.long sys_rt_sigtimedwait
	.long sys_rt_sigqueueinfo
	.long sys_rt_sigsuspend
	.long sys_pread64	/* 180 */
	.long sys_pwrite64
	.long sys_chown16
	.long sys_getcwd
	.long sys_capget
	.long sys_capset	/* 185 */
	.long sys_sigaltstack
	.long sys_sendfile
	.long sys_ni_syscall	/* reserved for streams1 */
	.long sys_ni_syscall	/* reserved for streams2 */
	.long sys_vfork		/* 190 */
	.long sys_getrlimit
	.long sys_mmap2
	.long sys_truncate64
	.long sys_ftruncate64
	.long sys_stat64	/* 195 */
	.long sys_lstat64
	.long sys_fstat64
	.long sys_lchown
	.long sys_getuid
	.long sys_getgid	/* 200 */
	.long sys_geteuid
	.long sys_getegid
	.long sys_setreuid
	.long sys_setregid
	.long sys_getgroups	/* 205 */
	.long sys_setgroups
	.long sys_fchown
	.long sys_setresuid
	.long sys_getresuid
	.long sys_setresgid	/* 210 */
	.long sys_getresgid
	.long sys_chown
	.long sys_setuid
	.long sys_setgid
	.long sys_setfsuid	/* 215 */
	.long sys_setfsgid
	.long sys_pivot_root
	.long sys_mincore
	.long sys_madvise
	.long sys_getdents64	/* 220 */
	.long sys_fcntl64
	.long sys_ni_syscall	/* reserved for TUX */
	.long sys_ni_syscall
	.long sys_gettid
	.long sys_readahead	/* 225 */
	.long sys_setxattr
	.long sys_lsetxattr
	.long sys_fsetxattr
	.long sys_getxattr
	.long sys_lgetxattr	/* 230 */
	.long sys_fgetxattr
	.long sys_listxattr
	.long sys_llistxattr
	.long sys_flistxattr
	.long sys_removexattr	/* 235 */
	.long sys_lremovexattr
	.long sys_fremovexattr
	.long sys_tkill
	.long sys_sendfile64
	.long sys_futex		/* 240 */
	.long sys_sched_setaffinity
	.long sys_sched_getaffinity
	.long sys_set_thread_area
	.long sys_get_thread_area
	.long sys_io_setup	/* 245 */
	.long sys_io_destroy
	.long sys_io_getevents
	.long sys_io_submit
	.long sys_io_cancel
	.long sys_fadvise64	/* 250 */
	.long sys_ni_syscall
	.long sys_exit_group
	.long sys_lookup_dcookie
	.long sys_epoll_create
	.long sys_epoll_ctl	/* 255 */
	.long sys_epoll_wait
 	.long sys_remap_file_pages
 	.long sys_set_tid_address
 	.long sys_timer_create
 	.long sys_timer_settime		/* 260 */
 	.long sys_timer_gettime
 	.long sys_timer_getoverrun
 	.long sys_timer_delete
 	.long sys_clock_settime
 	.long sys_clock_gettime		/* 265 */
 	.long sys_clock_getres
 	.long sys_clock_nanosleep
	.long sys_statfs64
	.long sys_fstatfs64	
	.long sys_tgkill	/* 270 */
	.long sys_utimes
 	.long sys_fadvise64_64
	.long sys_ni_syscall	/* sys_vserver */
	.long sys_mbind
	.long sys_get_mempolicy
	.long sys_set_mempolicy
	.long sys_mq_open
	.long sys_mq_unlink
	.long sys_mq_timedsend
	.long sys_mq_timedreceive	/* 280 */
	.long sys_mq_notify
	.long sys_mq_getsetattr
	.long sys_ni_syscall		/* reserved for kexec */
	.long sys_waitid
	.long sys_ni_syscall		/* 285 */ /* available */
	.long sys_add_key
	.long sys_request_key
	.long sys_keyctl

syscall_table_size=(.-sys_call_table)
