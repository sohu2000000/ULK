#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <asm/param.h>	/* for HZ */

#include <linux/config.h>
#include <linux/capability.h>
#include <linux/threads.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/rbtree.h>
#include <linux/thread_info.h>
#include <linux/cpumask.h>
#include <linux/errno.h>

#include <asm/system.h>
#include <asm/semaphore.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/mmu.h>
#include <asm/cputime.h>

#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/signal.h>
#include <linux/securebits.h>
#include <linux/fs_struct.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/percpu.h>
#include <linux/topology.h>

struct exec_domain;

/*
 * cloning flags:
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
/**
 * �����ڴ�������������ҳ��
 */
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
/**
 * ������Ŀ¼�͵�ǰ����Ŀ¼���ڵı����Լ������������ļ���ʼ����Ȩ��λ����ֵ
 */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
/**
 * �������ļ���
 */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
/**
 * �����źŴ�������ı��������źű��͹����źű�
 * ����ñ�־Ϊ1����ôһ��Ҫ����CLONE_VM
 */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
/**
 * ��������̱����٣���ô���ӽ���Ҳ�����١�
 * �����ǣ�debugger�������ϣ�����Լ���Ϊ�������������ӽ��̡�����������£��ں˰Ѹñ�־ǿ��Ϊ1
 */
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
/**
 * �ڷ���vforkϵͳ����ʱ����
 */
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
/**
 * �����ӽ��̵ĸ�����Ϊ���ý��̵ĸ����̡�
 */
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
/**
 * ���ӽ��̲��뵽�����̵�ͬһ�߳����С���ʹ�ӽ��̹��������̵��ź������������Ҳ�����ӽ��̵�tgid�ֶκ�group_leader�ֶΡ�
 * ��������־λΪ1�����������CLONE_SIGHAND��־��
 */
#define CLONE_THREAD	0x00010000	/* Same thread group? */
/**
 * ��clone��Ҫ�Լ��������ռ�ʱ�����øñ�־������ͬʱ���ñ���־��CLONE_FS��
 * ���clone()ϵͳ������CLONE_NEWNS��־����һ���½��̣���ô���̽���ȡһ���µ������ռ䣬�µ������ռ�������ӽ��̼̳�
 */
#define CLONE_NEWNS	0x00020000	/* New namespace group? */
/**
 * ����System V IPCȡ���ź����Ĳ�����
 */
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
/**
 * Ϊ���������̴����µ��ֲ߳̾��洢�Σ�TLS�����ö��ɲ���tls��ָ��Ľṹ����������
 */
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
/**
 * ���ӽ��̵�PIDд����ptid������ָ��ĸ����̵��û�̬������
 */
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
/**
 * ����ñ�־�����ã����ں˽���һ�ִ������ƣ������ӽ���Ҫ�˳���Ҫ��ʼִ���³���
 * ����Щ����£��ں˽�����ɲ���ctid��ָ����û�̬�����������ѵȴ�����¼����κν���
 */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
/**
 * ������־�������ں˺���
 */
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
/**
 * �ں����������־��ʹCLONE_PTRACE��־�ƶ����ã���ֹ�ں��̸߳��ٽ��̣�
 */
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
/**
 * ���ӽ��̵�PIDд����ctid������ָ����ӽ��̵��û�̬������
 */
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
/**
 * ǿ���ӽ��̿�ʼ��TASK_STOPPED״̬
 */
#define CLONE_STOPPED		0x02000000	/* Start in stopped state */

/*
 * List of flags we want to share for kernel threads,
 * if only because they are not used by them anyway.
 */
#define CLONE_KERNEL	(CLONE_FS | CLONE_FILES | CLONE_SIGHAND)

/*
 * These are the constant used to fake the fixed-point load-average
 * counting. Some notes:
 *  - 11 bit fractions expand to 22 bits by the multiplies: this gives
 *    a load-average precision of 10 bits integer + 11 bits fractional
 *  - if you want to count load-averages more often, you need more
 *    precision, or rounding will get you. With 2-second counting freq,
 *    the EXP_n values would be 1981, 2034 and 2043 if still using only
 *    11 bit fractions.
 */
extern unsigned long avenrun[];		/* Load averages */

#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define LOAD_FREQ	(5*HZ)		/* 5 sec intervals */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;

extern unsigned long total_forks;
extern int nr_threads;
extern int last_pid;
DECLARE_PER_CPU(unsigned long, process_counts);
extern int nr_processes(void);
extern unsigned long nr_running(void);
extern unsigned long nr_uninterruptible(void);
extern unsigned long nr_iowait(void);

#include <linux/time.h>
#include <linux/param.h>
#include <linux/resource.h>
#include <linux/timer.h>

#include <asm/processor.h>

/**
 * ����Ҫô��CPU��ִ�У�Ҫô׼��ִ�С�
 */
#define TASK_RUNNING		0
/**
 * ���жϵĵȴ�״̬��
 * ���̱�����ֱ��ĳ��������Ϊ�档����һ��Ӳ���жϣ��ͷŽ������ȴ���ϵͳ��Դ���򴫵�һ���źŶ��ǿ��Ի��ѽ��̵�����
 */
#define TASK_INTERRUPTIBLE	1
/**
 * �����жϵĵȴ�״̬��
 * ����������٣�������ʱҲ���ã�������̴�һ���豸�ļ�������Ӧ������������̽��Ӳ���豸ʱ����������״̬��
 * ��̽�����ǰ���豸��������������жϣ���ôӲ���豸��״̬���ܻᴦ�ڲ���Ԥ֪״̬��
 */
#define TASK_UNINTERRUPTIBLE	2
/**
 * ��ͣ״̬�����յ�SIGSTOP,SIGTSTP,SIGTTIN����SIGTTOU�źź󣬻�����״̬��
 */
#define TASK_STOPPED		4
/**
 * ������״̬�������̱�����һ�����̼��ʱ���κ��źŶ����԰�������ڸ�
 */
#define TASK_TRACED		8
/**
 * ����״̬�����̵�ִ�б���ֹ�����ǣ������̻�û�е�����wait4��waitpid�������й�
 * �������̵���Ϣ���ڴ�ʱ���ں˲����ͷ�������ݽṹ����Ϊ�����̿��ܻ���Ҫ����
 */
#define EXIT_ZOMBIE		16
/**
 * �ڸ����̵���wait4��ɾ��ǰ��Ϊ��������������ͬһ������Ҳִ��wait4����
 * ����״̬��EXIT_ZOMBIEתΪEXIT_DEAD������������״̬��
 */
#define EXIT_DEAD		32

#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
/**
 * ���ý���״̬��ͬʱ������ڴ����ϡ�
 */
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))

/**
 * ���õ�ǰ����״̬��ͬʱ������ڴ����ϡ�
 */
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))

/* Task command name length */
#define TASK_COMM_LEN 16

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2

struct sched_param {
	int sched_priority;
};

#ifdef __KERNEL__

#include <linux/spinlock.h>

/*
 * This serializes "schedule()" and also protects
 * the run-queue from deletions/modifications (but
 * _adding_ to the beginning of the run-queue has
 * a separate lock).
 */
extern rwlock_t tasklist_lock;
/**
 * �������ڴ������������ķ��ʡ�
 */
extern spinlock_t mmlist_lock;

typedef struct task_struct task_t;

extern void sched_init(void);
extern void sched_init_smp(void);
extern void init_idle(task_t *idle, int cpu);

extern cpumask_t nohz_cpu_mask;

extern void show_state(void);
extern void show_regs(struct pt_regs *);

/*
 * TASK is a pointer to the task whose backtrace we want to see (or NULL for current
 * task), SP is the stack pointer of the first frame that should be shown in the back
 * trace (or NULL if the entire call-chain of the task should be shown).
 */
extern void show_stack(struct task_struct *task, unsigned long *sp);

void io_schedule(void);
long io_schedule_timeout(long timeout);

extern void cpu_init (void);
extern void trap_init(void);
extern void update_process_times(int user);
extern void scheduler_tick(void);
extern unsigned long cache_decay_ticks;

/* Attach to any functions which should be ignored in wchan output. */
#define __sched		__attribute__((__section__(".sched.text")))
/* Is this address in the __sched functions? */
extern int in_sched_functions(unsigned long addr);

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX
extern signed long FASTCALL(schedule_timeout(signed long timeout));
asmlinkage void schedule(void);

struct namespace;

/* Maximum number of active map areas.. This is a random (large) number */
#define DEFAULT_MAX_MAP_COUNT	65536

extern int sysctl_max_map_count;

#include <linux/aio.h>

extern unsigned long
arch_get_unmapped_area(struct file *, unsigned long, unsigned long,
		       unsigned long, unsigned long);
extern unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags);
extern void arch_unmap_area(struct vm_area_struct *area);
extern void arch_unmap_area_topdown(struct vm_area_struct *area);


/**
 * �ڴ���������task_struct��mm�ֶ�ָ������
 * �������˽��̵�ַ�ռ��йص�ȫ����Ϣ��
 */
struct mm_struct {
	/**
	 * ָ�����������������ͷ��
	 */
	struct vm_area_struct * mmap;		/* list of VMAs */
	/**
	 * ָ������������ĺ�-�����ĸ�
	 */
	struct rb_root mm_rb;
	/**
	 * ָ�����һ�����õ�����������
	 */
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	/**
	 * �ڽ��̵�ַ�ռ���������Ч���Ե�ַ���ķ�����
	 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	/**
	 * �ͷ����Ե�ַ����ʱ���õķ�����
	 */
	void (*unmap_area) (struct vm_area_struct *area);
	/**
	 * ��ʶ��һ��������������������ļ��ڴ�ӳ������Ե�ַ��
	 */
	unsigned long mmap_base;		/* base of mmap area */
	/**
	 * �ں˴������ַ��ʼ�������̵�ַ�ռ������Ե�ַ�Ŀռ����䡣
	 */
	unsigned long free_area_cache;		/* first hole */
	/**
	 * ָ��ҳȫ��Ŀ¼��
	 */
	pgd_t * pgd;
	/**
	 * ��ʹ�ü���������Ź���mm_struct���ݽṹ�����������̵ĸ�����
	 */
	atomic_t mm_users;			/* How many users with user space? */
	/**
	 * ��ʹ�ü�������ÿ��mm_count�ݼ�ʱ���ں˶�Ҫ������Ƿ��Ϊ0,����ǣ���Ҫ�������ڴ���������
	 */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/**
	 * �������ĸ�����
	 */
	int map_count;				/* number of VMAs */
	/**
	 * �ڴ��������Ķ�д�ź�����
	 * ���������������ڼ������������̼乲����ͨ������ź������Ա��⾺��������
	 */
	struct rw_semaphore mmap_sem;
	/**
	 * ��������ҳ������������
	 */
	spinlock_t page_table_lock;		/* Protects page tables, mm->rss, mm->anon_rss */

	/**
	 * ָ���ڴ������������е�����Ԫ�ء�
	 */
	struct list_head mmlist;		/* List of maybe swapped mm's.  These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/**
	 * start_code-��ִ�д������ʼ��ַ��
	 * end_code-��ִ�д��������ַ��
	 * start_data-�ѳ�ʼ�����ݵ���ʼ��ַ��
	 * end_data--�ѳ�ʼ�����ݵĽ�����ַ��
	 */
	unsigned long start_code, end_code, start_data, end_data;
	/**
	 * start_brk-�ѵĳ�ʼ��ַ��
	 * brk-�ѵĵ�ǰ����ַ��
	 * start_stack-�û�̬��ջ����ʼ��ַ��
	 */
	unsigned long start_brk, brk, start_stack;
	/**
	 * arg_start-�����в�������ʼ��ַ��
	 * arg_end-�����в����Ľ�����ַ��
	 * env_start-������������ʼ��ַ��
	 * env_end-���������Ľ�����ַ��
	 */
	unsigned long arg_start, arg_end, env_start, env_end;
	/**
	 * rss-��������̵�ҳ������
	 * anon_rss-����������ڴ�ӳ���ҳ������s
	 * total_vm-���̵�ַ�ռ�Ĵ�С(ҳ����)
	 * locked_vm-��ס�����ܻ�����ҳ�ĸ�����
	 * shared_vm-�����ļ��ڴ�ӳ���е�ҳ����
	 */
	unsigned long rss, anon_rss, total_vm, locked_vm, shared_vm;
	/**
	 * exec_vm-��ִ���ڴ�ӳ���ҳ����
	 * stack_vm-�û�̬��ջ�е�ҳ����
	 * reserved_vm-�ڱ������е�ҳ�����������������е�ҳ����
	 * def_flags-������Ĭ�ϵķ��ʱ�־��
	 * nr_ptes-this���̵�ҳ������
	 */
	unsigned long exec_vm, stack_vm, reserved_vm, def_flags, nr_ptes;

	/**
	 * ��ʼִ��elf����ʱʹ�á�
	 */
	unsigned long saved_auxv[42]; /* for /proc/PID/auxv */

	/**
	 * ��ʾ�Ƿ���Բ����ڴ���Ϣת���ı�־��
	 */
	unsigned dumpable:1;
	/**
	 * ����TLB������λ���롣
	 */
	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	/**
	 * ������ϵ�ṹ��Ϣ�ı���
	 * ��80X86ƽ̨�ϵ�LDT��ַ��
	 */
	mm_context_t context;

	/* Token based thrashing protection. */
	/**
	 * �������ʸ��ý�����ǵ�ʱ�䡣
	 */
	unsigned long swap_token_time;
	/**
	 * ��������������ȱҳ�������øñ�־��
	 */
	char recent_pagein;

	/* coredumping support */
	/**
	 * ���ڰѽ��̵�ַ�ռ������ж�ص�ת���ļ��е����������̵�������
	 */
	int core_waiters;
	/**
	 * core_startup_done-ָ�򴴽��ڴ�ת���ļ�ʱ�Ĳ���ԭ�
	 * core_done-�����ڴ�ת���ļ�ʱʹ�õĲ���ԭ�
	 */
	struct completion *core_startup_done, core_done;

	/* aio bits */
	/**
	 * ���ڱ����첽IO����������������
	 */
	rwlock_t		ioctx_list_lock;
	/**
	 * �첽IO������������
	 * һ��Ӧ�ÿ��Դ������AIO������һ���������̵����е�kioctx�����������һ�����������У�������λ��ioctx_list�ֶ�
	 */
	struct kioctx		*ioctx_list;

	/**
	 * Ĭ�ϵ��첽IO�����ġ�
	 */
	struct kioctx		default_kioctx;

	/**
	 * ������ӵ�е����ҳ������
	 */
	unsigned long hiwater_rss;	/* High-water RSS usage */
	/**
	 * �����������е����ҳ����
	 */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */
};

/**
 * �źŴ�������������
 */
struct sighand_struct {
	/**
	 * �źŴ�������������ʹ�ü�������
	 */
	atomic_t		count;
	/**
	 * ˵�����������ź���ִ�в����Ľṹ���顣
	 */
	struct k_sigaction	action[_NSIG];
	/**
	 * �����ź����������źŴ�����������������������
	 */
	spinlock_t		siglock;
};

/*
 * NOTE! "signal_struct" does not have it's own
 * locking, because a shared signal_struct always
 * implies a shared sighand_struct, so locking
 * sighand_struct is always a proper superset of
 * the locking of signal_struct.
 */
/**
 * �ź���������������ͬһ�߳�������н��̹�����
 */
struct signal_struct {
	/**
	 * ��������ʹ�ü�����
	 */
	atomic_t		count;
	/**
	 * �߳����л���̵�������
	 */
	atomic_t		live;

	/**
	 * ��ϵͳ����wait4��˯�ߵĽ��̵ĵȴ����С�
	 */
	wait_queue_head_t	wait_chldexit;	/* for wait4() */

	/* current thread group signal load-balancing target: */
	/**
	 * �����źŵ��߳����У����һ�����̵���������
	 */
	task_t			*curr_target;

	/* shared signal handling: */
	/**
	 * ��Ź��������źŵ����ݽṹ��
	 */
	struct sigpending	shared_pending;

	/* thread group exit support */
	/**
	 * �߳���Ľ�����ֹ����
	 */
	int			group_exit_code;
	/* overloaded:
	 * - notify group_exit_task when ->count is equal to notify_count
	 * - everyone except group_exit_task is stopped during signal delivery
	 *   of fatal signals, group_exit_task processes the signal.
	 */
	/**
	 * ɱ�������߳����ʱ��ʹ��
	 */
	struct task_struct	*group_exit_task;
	/**
	 * ɱ�������߳����ʱ��ʹ��
	 */
	int			notify_count;

	/* thread group stop support, overloads group_exit_code too */
	/**
	 * ֹͣ�����߳����ʱ��ʹ��
	 */
	int			group_stop_count;
	/**
	 * �ڴ����޸Ľ���״̬���ź�ʱʹ�õı�־��
	 */
	unsigned int		flags; /* see SIGNAL_* flags below */

	/* POSIX.1b Interval Timers */
	struct list_head posix_timers;

	/* job control IDs */
	/**
	 * ����ͷ����
	 */
	pid_t pgrp;
	pid_t tty_old_pgrp;
	/**
	 * �Ự��ͷ���̡�
	 */
	pid_t session;
	/* boolean value for session group leader */
	int leader;
	
	/**
	 * �������ص�tty.
	 */
	struct tty_struct *tty; /* NULL if no tty */

	/*
	 * Cumulative resource counters for dead threads in the group,
	 * and for reaped dead child processes forked by this group.
	 * Live threads maintain their own counters and add to these
	 * in __exit_signal, except for the group leader.
	 */
	cputime_t utime, stime, cutime, cstime;
	unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
	unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;

	/*
	 * We don't bother to synchronize most readers of this at all,
	 * because there is no reader checking a limit that actually needs
	 * to get both rlim_cur and rlim_max atomically, and either one
	 * alone is a single word that can safely be read normally.
	 * getrlimit/setrlimit use task_lock(current->group_leader) to
	 * protect this instead of the siglock, because they really
	 * have no need to disable irqs.
	 */
	/**
	 * ��Դ��������
	 */
	struct rlimit rlim[RLIM_NLIMITS];
};

/*
 * Bits in flags field of signal_struct.
 */
#define SIGNAL_STOP_STOPPED	0x00000001 /* job control stop in effect */
#define SIGNAL_STOP_DEQUEUED	0x00000002 /* stop signal dequeued */
#define SIGNAL_STOP_CONTINUED	0x00000004 /* SIGCONT since WCONTINUED reap */
#define SIGNAL_GROUP_EXIT	0x00000008 /* group exit in progress */


/*
 * Priority of a process goes from 0..MAX_PRIO-1, valid RT
 * priority is 0..MAX_RT_PRIO-1, and SCHED_NORMAL tasks are
 * in the range MAX_RT_PRIO..MAX_PRIO-1. Priority values
 * are inverted: lower p->prio value means higher priority.
 *
 * The MAX_USER_RT_PRIO value allows the actual maximum
 * RT priority to be separate from the value exported to
 * user-space.  This allows kernel threads to set their
 * priority to a value higher than any user task. Note:
 * MAX_RT_PRIO must not be smaller than MAX_USER_RT_PRIO.
 */

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO

#define MAX_PRIO		(MAX_RT_PRIO + 40)

#define rt_task(p)		(unlikely((p)->prio < MAX_RT_PRIO))

/*
 * Some day this will be a full-fledged user tracking system..
 */
struct user_struct {
	atomic_t __count;	/* reference count */
	atomic_t processes;	/* How many processes does this user have? */
	atomic_t files;		/* How many open files does this user have? */
	atomic_t sigpending;	/* How many pending signals does this user have? */
	/* protected by mq_lock	*/
	unsigned long mq_bytes;	/* How many bytes can be allocated to mqueue? */
	unsigned long locked_shm; /* How many pages of mlocked shm ? */

#ifdef CONFIG_KEYS
	struct key *uid_keyring;	/* UID specific keyring */
	struct key *session_keyring;	/* UID's default session keyring */
#endif

	/* Hash table maintenance information */
	struct list_head uidhash_list;
	uid_t uid;
};

extern struct user_struct *find_user(uid_t);

extern struct user_struct root_user;
#define INIT_USER (&root_user)

typedef struct prio_array prio_array_t;
struct backing_dev_info;
struct reclaim_state;

#ifdef CONFIG_SCHEDSTATS
struct sched_info {
	/* cumulative counters */
	unsigned long	cpu_time,	/* time spent on the cpu */
			run_delay,	/* time spent waiting on a runqueue */
			pcnt;		/* # of timeslices run on this cpu */

	/* timestamps */
	unsigned long	last_arrival,	/* when we last ran on a cpu */
			last_queued;	/* when we were last queued to run */
};

extern struct file_operations proc_schedstat_operations;
#endif

enum idle_type
{
	SCHED_IDLE,
	NOT_IDLE,
	NEWLY_IDLE,
	MAX_IDLE_TYPES
};

/*
 * sched-domains (multiprocessor balancing) declarations:
 */
#ifdef CONFIG_SMP
#define SCHED_LOAD_SCALE	128UL	/* increase resolution of load */

#define SD_LOAD_BALANCE		1	/* Do load balancing on this domain. */
#define SD_BALANCE_NEWIDLE	2	/* Balance when about to become idle */
#define SD_BALANCE_EXEC		4	/* Balance on exec */
#define SD_WAKE_IDLE		8	/* Wake to idle CPU on task wakeup */
#define SD_WAKE_AFFINE		16	/* Wake task to waking CPU */
#define SD_WAKE_BALANCE		32	/* Perform balancing at task wakeup */
#define SD_SHARE_CPUPOWER	64	/* Domain members share cpu power */

/**
 * ���������
 */
struct sched_group {
	struct sched_group *next;	/* Must be a circular list */
	cpumask_t cpumask;

	/*
	 * CPU power of this group, SCHED_LOAD_SCALE being max power for a
	 * single CPU. This is read only (except for setup, hotplug CPU).
	 */
	unsigned long cpu_power;
};

/**
 * ������
 */
struct sched_domain {
	/* These fields must be setup */
	/**
	 * ��������
	 */
	struct sched_domain *parent;	/* top domain must be null terminated */
	/**
	 * ���������ĵ�һ��Ԫ�ء�
	 */
	struct sched_group *groups;	/* the balancing groups of the domain */
	cpumask_t span;			/* span of all CPUs in this domain */
	unsigned long min_interval;	/* Minimum balance interval ms */
	unsigned long max_interval;	/* Maximum balance interval ms */
	unsigned int busy_factor;	/* less balancing by factor if busy */
	unsigned int imbalance_pct;	/* No balance until over watermark */
	unsigned long long cache_hot_time; /* Task considered cache hot (ns) */
	unsigned int cache_nice_tries;	/* Leave cache hot tasks for # tries */
	unsigned int per_cpu_gain;	/* CPU % gained by adding domain cpus */
	int flags;			/* See SD_* */

	/* Runtime fields. */
	unsigned long last_balance;	/* init to jiffies. units in jiffies */
	unsigned int balance_interval;	/* initialise to 1. units in ms. */
	unsigned int nr_balance_failed; /* initialise to 0 */

#ifdef CONFIG_SCHEDSTATS
	/* load_balance() stats */
	unsigned long lb_cnt[MAX_IDLE_TYPES];
	unsigned long lb_failed[MAX_IDLE_TYPES];
	unsigned long lb_imbalance[MAX_IDLE_TYPES];
	unsigned long lb_nobusyg[MAX_IDLE_TYPES];
	unsigned long lb_nobusyq[MAX_IDLE_TYPES];

	/* sched_balance_exec() stats */
	unsigned long sbe_attempts;
	unsigned long sbe_pushed;

	/* try_to_wake_up() stats */
	unsigned long ttwu_wake_affine;
	unsigned long ttwu_wake_balance;
#endif
};

#ifdef ARCH_HAS_SCHED_DOMAIN
/* Useful helpers that arch setup code may use. Defined in kernel/sched.c */
extern cpumask_t cpu_isolated_map;
extern void init_sched_build_groups(struct sched_group groups[],
	                        cpumask_t span, int (*group_fn)(int cpu));
extern void cpu_attach_domain(struct sched_domain *sd, int cpu);
#endif /* ARCH_HAS_SCHED_DOMAIN */
#endif /* CONFIG_SMP */


struct io_context;			/* See blkdev.h */
void exit_io_context(void);

#define NGROUPS_SMALL		32
#define NGROUPS_PER_BLOCK	((int)(PAGE_SIZE / sizeof(gid_t)))
struct group_info {
	int ngroups;
	atomic_t usage;
	gid_t small_block[NGROUPS_SMALL];
	int nblocks;
	gid_t *blocks[0];
};

/*
 * get_group_info() must be called with the owning task locked (via task_lock())
 * when task != current.  The reason being that the vast majority of callers are
 * looking at current->group_info, which can not be changed except by the
 * current task.  Changing current->group_info requires the task lock, too.
 */
#define get_group_info(group_info) do { \
	atomic_inc(&(group_info)->usage); \
} while (0)

#define put_group_info(group_info) do { \
	if (atomic_dec_and_test(&(group_info)->usage)) \
		groups_free(group_info); \
} while (0)

struct group_info *groups_alloc(int gidsetsize);
void groups_free(struct group_info *group_info);
int set_current_groups(struct group_info *group_info);
/* access the groups "array" with this macro */
#define GROUP_AT(gi, i) \
    ((gi)->blocks[(i)/NGROUPS_PER_BLOCK][(i)%NGROUPS_PER_BLOCK])


struct audit_context;		/* See audit.c */
struct mempolicy;

struct task_struct {
	/**
	 * ����״̬��
	 */
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	/**
	 * ���̵Ļ�����Ϣ��
	 */
	struct thread_info *thread_info;
	atomic_t usage;
	unsigned long flags;	/* per process flags, defined below */
	unsigned long ptrace;

	int lock_depth;		/* Lock depth */

	/**
	 * ���еĶ�̬����Ȩ�;�̬����Ȩ
	 */
	int prio, static_prio;
	/**
	 * �����������ж��С�ÿ�����ȼ���Ӧһ�����ж��С�
	 */
	struct list_head run_list;
	/**
	 * ָ��ǰ���ж��е�prio_array_t
	 */
	prio_array_t *array;

	/**
	 * ���̵�ƽ��˯��ʱ��
	 */
	unsigned long sleep_avg;
	/**
	 * timestamp-��������������ж��е�ʱ�䡣���漰�����̵����һ�ν����л���ʱ��
	 * last_ran-���һ���滻�����̵Ľ����л�ʱ�䡣
	 */
	unsigned long long timestamp, last_ran;
	/**
	 * ���̱�����ʱ��ʹ�õĴ��롣
	 *     0:���̴���TASK_RUNNING״̬��
	 *     1:���̴���TASK_INTERRUPTIBLE����TASK_STOPPED״̬���������ڱ�ϵͳ���÷������̻��ں��̻߳��ѡ�
	 *     2:���̴���TASK_INTERRUPTIBLE����TASK_STOPPED״̬���������ڱ�ISR���߿��ӳٺ������ѡ�
	 *     -1:��ʾ��UNINTERRUPTIBLE״̬������
	 */
	int activated;

	/**
	 * ���̵ĵ�������:sched_normal,sched_rr����sched_fifo
	 */
	unsigned long policy;
	/**
	 * ��ִ�н��̵�CPU��λ����
	 */
	cpumask_t cpus_allowed;
	/**
	 * time_slice-�ڽ��̵�ʱ��Ƭ�У���ʣ���ʱ�ӽ�������
	 * first_time_slice-������̿϶�����������ʱ��Ƭ���ͰѸñ�־����Ϊ1.
	 *            xie.baoyouע:ԭ�����,Ӧ���Ǳ�ʾ�����Ƿ��ǵ�һ��ִ�С�����������ǵ�һ��ִ�У������ڿ�ʼ����
	 *                         �ĵ�һ��ʱ��Ƭ�ھ�������ϣ���ô�ͽ�ʣ���ʱ��Ƭ���������̡���Ҫ�ǿ��ǵ��н���
	 *                         ������Ķ�̬�����ӽ���ʱ�����ӽ��̻������˳�������������������������ʱ��Ƭ��������ֽ��̲���ƽ��
	 */
	unsigned int time_slice, first_time_slice;

#ifdef CONFIG_SCHEDSTATS
	struct sched_info sched_info;
#endif

	/**
	 * ͨ�������������н������ӵ�һ��˫�������С�
	 */
	struct list_head tasks;
	/*
	 * ptrace_list/ptrace_children forms the list of my children
	 * that were stolen by a ptracer.
	 */
	/**
	 * ������ͷ���������������б�debugger������ٵ�P���ӽ��̡�
	 */
	struct list_head ptrace_children;
	/**
	 * ָ�������ٽ�����ʵ�ʸ�����������ǰһ����һ��Ԫ�ء�
	 */
	struct list_head ptrace_list;

	/**
	 * mm:ָ���ڴ�����������ָ��
	 * mm�ֶ�ָ�������ӵ�е��ڴ�����������active_mm�ֶ�ָ���������ʱ��ʹ�õ��ڴ�������
	 * ������ͨ���̶��ѣ��������ֶδ����ͬ��ָ�룬���ǣ��ں��̲߳�ӵ���κ��ڴ�����������ˣ����ǵ�mm�ֶ�����ΪNULL
	 * ���ں��̵߳�������ʱ������active_mm�ֶα���ʼ��Ϊǰһ�����н��̵�active_mmֵ
	 */
	struct mm_struct *mm, *active_mm;

/* task state */
	struct linux_binfmt *binfmt;
	long exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	/* ??? */
	unsigned long personality;
	/**
	 * ���̷���execveϵͳ���õĴ�����
	 */
	unsigned did_exec:1;
	/**
	 * ����PID
	 */
	pid_t pid;
	/**
	 * �߳�����ͷ�̵߳�PID��
	 */
	pid_t tgid;
	/* 
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with 
	 * p->parent->pid)
	 */
	/**
	 * ָ�򴴽����̵Ľ��̵���������
	 * ������̵ĸ����̲��ٴ��ڣ���ָ�����1����������
	 * ��ˣ�����û�����һ����̨���̶����˳���shell����̨���̾ͻ��Ϊinit���ӽ��̡�
	 */
	struct task_struct *real_parent; /* real parent process (when being debugged) */
	/**
	 * ָ����̵ĵ�ǰ�����̡����ֽ��̵��ӽ�����ֹʱ�������򸸽��̷��źš�
	 * ����ֵͨ����real_parentһ�¡�
	 * ��ż��Ҳ���Բ�ͬ�����磺����һ�����̷�����ؽ��̵�ptraceϵͳ��������ʱ��
	 */
	struct task_struct *parent;	/* parent process */
	/*
	 * children/sibling forms the list of my children plus the
	 * tasks I'm ptracing.
	 */
	/**
	 * ����ͷ��������ָ�������Ԫ�ض��ǽ��̴������ӽ��̡�
	 */
	struct list_head children;	/* list of my children */
	/**
	 * ָ���ֵܽ�����������һ��Ԫ�ػ�ǰһ��Ԫ�ص�ָ�롣
	 */
	struct list_head sibling;	/* linkage in my parent's children list */
	/**
	 * P���ڽ��������ͷ���̵�������ָ�롣
	 */
	struct task_struct *group_leader;	/* threadgroup leader */

	/* PID/PID hash table linkage. */
	/**
	 * PIDɢ�б���ͨ�����ĸ��������Է���Ĳ���ͬһ�߳���������̣߳�ͬһ�Ự���������̵ȵȡ�
	 */
	struct pid pids[PIDTYPE_MAX];

	struct completion *vfork_done;		/* for vfork() */
	/**
	 * �ӽ������û�̬�ĵ�ַ����Щ�û�̬��ַ��ֵ�������û��������
	 * ��do_forkʱ��¼��Щ��ַ���Ժ������û���������ǵ�ֵ��
	 */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	/**
	 * ���̵�ʵʱ���ȼ���
	 */
	unsigned long rt_priority;
	/**
	 * ��������ֵ�����û�̬�Ķ�ʱ��������ʱ������ʱ�������û�̬���̷����źš�
	 * ÿһ��ֵ�ֱ����������ź�֮���Խ���Ϊ��λ�ļ��������ʱ���ĵ�ǰֵ��
	 */
	unsigned long it_real_value, it_real_incr;
	cputime_t it_virt_value, it_virt_incr;
	cputime_t it_prof_value, it_prof_incr;
	/**
	 * ÿ�����̵Ķ�̬��ʱ��������ʵ��ITIMER_REAL���͵ļ����ʱ����
	 * ��settimerϵͳ���ó�ʼ����
	 */
	struct timer_list real_timer;
	/**
	 * �������û�̬���ں�̬�¾����Ľ�����
	 */
	cputime_t utime, stime;
	unsigned long nvcsw, nivcsw; /* context switch counts */
	struct timespec start_time;
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;
/* process credentials */
	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	struct group_info *group_info;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
	unsigned keep_capabilities:1;
	struct user_struct *user;
#ifdef CONFIG_KEYS
	struct key *session_keyring;	/* keyring inherited over fork */
	struct key *process_keyring;	/* keyring private to this process (CLONE_THREAD) */
	struct key *thread_keyring;	/* keyring private to this thread */
#endif
	int oomkilladj; /* OOM kill score adjustment (bit shift). */
	char comm[TASK_COMM_LEN];
/* file system info */
	/**
	 * �ļ�ϵͳ�ڲ���·��ʱʹ�ã�����������Ӳ�����ȹ��������ѭ����
	 * link_count��__do_follow_link�ݹ���õĲ�Ρ�
	 * total_link_count����__do_follow_link���ܴ�����
	 */
	int link_count, total_link_count;
/* ipc stuff */
	struct sysv_sem sysvsem;
/* CPU-specific state of this task */
	struct thread_struct thread;
/* filesystem information */
	/**
	 * ���ļ�ϵͳ��ص���Ϣ���統ǰĿ¼��
	 */
	struct fs_struct *fs;
/* open file information */
	/**
	 * ָ���ļ���������ָ��
	 */
	struct files_struct *files;
/* namespace */
	struct namespace *namespace;
/* signal handlers */
	/**
	 * ָ����̵��ź���������ָ��
	 */
	struct signal_struct *signal;
	/**
	 * ָ����̵��źŴ���������������ָ��
	 */
	struct sighand_struct *sighand;

	/**
	 * blocked-���������źŵ�����
	 * real_blocked-�������źŵ���ʱ���루��rt_sigtimedwaitϵͳ����ʹ�ã�
	 */
	sigset_t blocked, real_blocked;
	/**
	 * ���˽�й����źŵ����ݽṹ
	 */
	struct sigpending pending;

	/**
	 * �źŴ��������ö�ջ�ĵ�ַ
	 */
	unsigned long sas_ss_sp;
	/**
	 * �źŴ��������ö�ջ�Ĵ�С
	 */
	size_t sas_ss_size;
	/**
	 * ָ��һ��������ָ�룬�豸��������ʹ����������������̵�ĳЩ�ź�
	 */
	int (*notifier)(void *priv);
	/**
	 * ָ��notifier��������ʹ�õ�����
	 */
	void *notifier_data;
	/*
	 * �豸��������ͨ��notifier �������������źŵ�λ����
	 */
	sigset_t *notifier_mask;
	
	void *security;
	struct audit_context *audit_context;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings */
	spinlock_t alloc_lock;
/* Protection of proc_dentry: nesting proc_lock, dcache_lock, write_lock_irq(&tasklist_lock); */
	spinlock_t proc_lock;
/* context-switch lock */
	spinlock_t switch_lock;

/* journalling filesystem info */
	/**
	 * ��ǰ���־���������ĵ�ַ��
	 */
	void *journal_info;

/* VM state */
	struct reclaim_state *reclaim_state;

	struct dentry *proc_dentry;
	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
/*
 * current io wait handle: wait queue entry to use for io waits
 * If this thread is processing aio, this points at the waitqueue
 * inside the currently handled kiocb. It may be NULL (i.e. default
 * to a stack based synchronous wait) if its doing sync IO.
 */
	wait_queue_t *io_wait;
/* i/o counters(bytes read/written, #syscalls */
	u64 rchar, wchar, syscr, syscw;
#if defined(CONFIG_BSD_PROCESS_ACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	clock_t acct_stimexpd;	/* clock_t-converted stime since last update */
#endif
#ifdef CONFIG_NUMA
  	struct mempolicy *mempolicy;
	short il_next;
#endif
};

static inline pid_t process_group(struct task_struct *tsk)
{
	return tsk->signal->pgrp;
}

/**
 * pid_alive - check that a task structure is not stale
 * @p: Task structure to be checked.
 *
 * Test if a process is not yet dead (at most zombie state)
 * If pid_alive fails, then pointers within the task structure
 * can be stale and must not be dereferenced.
 */
static inline int pid_alive(struct task_struct *p)
{
	return p->pids[PIDTYPE_PID].nr != 0;
}

extern void free_task(struct task_struct *tsk);
extern void __put_task_struct(struct task_struct *tsk);
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define put_task_struct(tsk) \
do { if (atomic_dec_and_test(&(tsk)->usage)) __put_task_struct(tsk); } while(0)

/*
 * Per process flags
 */
#define PF_ALIGNWARN	0x00000001	/* Print alignment warning msgs */
					/* Not implemented yet, only for 486*/
#define PF_STARTING	0x00000002	/* being created */
#define PF_EXITING	0x00000004	/* getting shut down */
#define PF_DEAD		0x00000008	/* Dead */
/**
 * ���̻�û�з�����execveϵͳ����
 */
#define PF_FORKNOEXEC	0x00000040	/* forked but didn't exec */
/**
 * �����Ƿ�ʹ����ĳ�ֳ����û�Ȩ��
 */
#define PF_SUPERPRIV	0x00000100	/* used super-user privileges */
#define PF_DUMPCORE	0x00000200	/* dumped core */
#define PF_SIGNALED	0x00000400	/* killed by a signal */
#define PF_MEMALLOC	0x00000800	/* Allocating memory */
#define PF_FLUSHER	0x00001000	/* responsible for disk writeback */
/**
 * 
 */
#define PF_USED_MATH	0x00002000	/* if unset the fpu must be initialized before use */
#define PF_FREEZE	0x00004000	/* this task is being frozen for suspend now */
#define PF_NOFREEZE	0x00008000	/* this thread should not be frozen */
#define PF_FROZEN	0x00010000	/* frozen for system suspend */
#define PF_FSTRANS	0x00020000	/* inside a filesystem transaction */
#define PF_KSWAPD	0x00040000	/* I am kswapd */
/**
 * ���øñ�־λ����ҳ�����ز���ʱ��OOM����select_bad_process��ǿ��ѡ��ɾ���ý��̡�
 */
#define PF_SWAPOFF	0x00080000	/* I am in swapoff */
#define PF_LESS_THROTTLE 0x00100000	/* Throttle me less: I clean memory */
#define PF_SYNCWRITE	0x00200000	/* I am doing a sync write */
#define PF_BORROWED_MM	0x00400000	/* I am a kthread doing use_mm */

/*
 * Only the _current_ task can read/write to tsk->flags, but other
 * tasks can access tsk->flags in readonly mode for example
 * with tsk_used_math (like during threaded core dumping).
 * There is however an exception to this rule during ptrace
 * or during fork: the ptracer task is allowed to write to the
 * child->flags of its traced child (same goes for fork, the parent
 * can write to the child->flags), because we're guaranteed the
 * child is not running and in turn not changing child->flags
 * at the same time the parent does it.
 */
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define set_used_math() set_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
/* NOTE: this will return 0 or PF_USED_MATH, it will never return 1 */
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)

#ifdef CONFIG_SMP
extern int set_cpus_allowed(task_t *p, cpumask_t new_mask);
#else
static inline int set_cpus_allowed(task_t *p, cpumask_t new_mask)
{
	if (!cpus_intersects(new_mask, cpu_online_map))
		return -EINVAL;
	return 0;
}
#endif

extern unsigned long long sched_clock(void);

/* sched_exec is called by processes performing an exec */
#ifdef CONFIG_SMP
extern void sched_exec(void);
#else
#define sched_exec()   {}
#endif

#ifdef CONFIG_HOTPLUG_CPU
extern void idle_task_exit(void);
#else
static inline void idle_task_exit(void) {}
#endif

extern void sched_idle_next(void);
extern void set_user_nice(task_t *p, long nice);
extern int task_prio(const task_t *p);
extern int task_nice(const task_t *p);
extern int task_curr(const task_t *p);
extern int idle_cpu(int cpu);
extern int sched_setscheduler(struct task_struct *, int, struct sched_param *);
extern task_t *idle_task(int cpu);

void yield(void);

/*
 * The default (Linux) execution domain.
 */
extern struct exec_domain	default_exec_domain;

/**
 * �ں�ջ��thread_info�������塣
 */
union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

extern union thread_union init_thread_union;
extern struct task_struct init_task;

extern struct   mm_struct init_mm;

#define find_task_by_pid(nr)	find_task_by_pid_type(PIDTYPE_PID, nr)
extern struct task_struct *find_task_by_pid_type(int type, int pid);
extern void set_special_pids(pid_t session, pid_t pgrp);
extern void __set_special_pids(pid_t session, pid_t pgrp);

/* per-UID process charging. */
extern struct user_struct * alloc_uid(uid_t);
static inline struct user_struct *get_uid(struct user_struct *u)
{
	atomic_inc(&u->__count);
	return u;
}
extern void free_uid(struct user_struct *);
extern void switch_uid(struct user_struct *);

#include <asm/current.h>

extern void do_timer(struct pt_regs *);

extern int FASTCALL(wake_up_state(struct task_struct * tsk, unsigned int state));
extern int FASTCALL(wake_up_process(struct task_struct * tsk));
extern void FASTCALL(wake_up_new_task(struct task_struct * tsk,
						unsigned long clone_flags));
#ifdef CONFIG_SMP
 extern void kick_process(struct task_struct *tsk);
#else
 static inline void kick_process(struct task_struct *tsk) { }
#endif
extern void FASTCALL(sched_fork(task_t * p));
extern void FASTCALL(sched_exit(task_t * p));

extern int in_group_p(gid_t);
extern int in_egroup_p(gid_t);

extern void proc_caches_init(void);
extern void flush_signals(struct task_struct *);
extern void flush_signal_handlers(struct task_struct *, int force_default);
extern int dequeue_signal(struct task_struct *tsk, sigset_t *mask, siginfo_t *info);

static inline int dequeue_signal_lock(struct task_struct *tsk, sigset_t *mask, siginfo_t *info)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&tsk->sighand->siglock, flags);
	ret = dequeue_signal(tsk, mask, info);
	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);

	return ret;
}	

extern void block_all_signals(int (*notifier)(void *priv), void *priv,
			      sigset_t *mask);
extern void unblock_all_signals(void);
extern void release_task(struct task_struct * p);
extern int send_sig_info(int, struct siginfo *, struct task_struct *);
extern int send_group_sig_info(int, struct siginfo *, struct task_struct *);
extern int force_sigsegv(int, struct task_struct *);
extern int force_sig_info(int, struct siginfo *, struct task_struct *);
extern int __kill_pg_info(int sig, struct siginfo *info, pid_t pgrp);
extern int kill_pg_info(int, struct siginfo *, pid_t);
extern int kill_proc_info(int, struct siginfo *, pid_t);
extern void do_notify_parent(struct task_struct *, int);
extern void force_sig(int, struct task_struct *);
extern void force_sig_specific(int, struct task_struct *);
extern int send_sig(int, struct task_struct *, int);
extern void zap_other_threads(struct task_struct *p);
extern int kill_pg(pid_t, int, int);
extern int kill_sl(pid_t, int, int);
extern int kill_proc(pid_t, int, int);
extern struct sigqueue *sigqueue_alloc(void);
extern void sigqueue_free(struct sigqueue *);
extern int send_sigqueue(int, struct sigqueue *,  struct task_struct *);
extern int send_group_sigqueue(int, struct sigqueue *,  struct task_struct *);
extern int do_sigaction(int, const struct k_sigaction *, struct k_sigaction *);
extern int do_sigaltstack(const stack_t __user *, stack_t __user *, unsigned long);

/* These can be the second arg to send_sig_info/send_group_sig_info.  */
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SEND_SIG_PRIV	((struct siginfo *) 1)
#define SEND_SIG_FORCED	((struct siginfo *) 2)

/* True if we are on the alternate signal stack.  */

static inline int on_sig_stack(unsigned long sp)
{
	return (sp - current->sas_ss_sp < current->sas_ss_size);
}

static inline int sas_ss_flags(unsigned long sp)
{
	return (current->sas_ss_size == 0 ? SS_DISABLE
		: on_sig_stack(sp) ? SS_ONSTACK : 0);
}


#ifdef CONFIG_SECURITY
/* code is in security.c */
extern int capable(int cap);
#else
/**
 * ��鵱ǰ�����Ƿ���ĳ��Ȩ��
 */
static inline int capable(int cap)
{
	if (cap_raised(current->cap_effective, cap)) {
		current->flags |= PF_SUPERPRIV;
		return 1;
	}
	return 0;
}
#endif

/*
 * Routines for handling mm_structs
 */
extern struct mm_struct * mm_alloc(void);

/* mmdrop drops the mm and the page tables */
extern void FASTCALL(__mmdrop(struct mm_struct *));
/*
 * ��mm_count�ֶμ�ȥ1������ֶ�Ϊ0�����ͷ�mm_struct�ṹ
 */
static inline void mmdrop(struct mm_struct * mm)
{
	if (atomic_dec_and_test(&mm->mm_count))
		__mmdrop(mm); /*��*/
}

/* mmput gets rid of the mappings and all user-space */
extern void mmput(struct mm_struct *);
/* Grab a reference to a task's mm, if it is not already going away */
extern struct mm_struct *get_task_mm(struct task_struct *task);
/* Remove the current tasks stale references to the old mm_struct */
extern void mm_release(struct task_struct *, struct mm_struct *);

extern int  copy_thread(int, unsigned long, unsigned long, unsigned long, struct task_struct *, struct pt_regs *);
extern void flush_thread(void);
extern void exit_thread(void);

extern void exit_mm(struct task_struct *);
extern void exit_files(struct task_struct *);
extern void exit_signal(struct task_struct *);
extern void __exit_signal(struct task_struct *);
extern void exit_sighand(struct task_struct *);
extern void __exit_sighand(struct task_struct *);
extern void exit_itimers(struct signal_struct *);

extern NORET_TYPE void do_group_exit(int);

extern void reparent_to_init(void);
extern void daemonize(const char *, ...);
extern int allow_signal(int);
extern int disallow_signal(int);
extern task_t *child_reaper;

extern int do_execve(char *, char __user * __user *, char __user * __user *, struct pt_regs *);
extern long do_fork(unsigned long, unsigned long, struct pt_regs *, unsigned long, int __user *, int __user *);
task_t *fork_idle(int);

extern void set_task_comm(struct task_struct *tsk, char *from);
extern void get_task_comm(char *to, struct task_struct *tsk);

#ifdef CONFIG_SMP
extern void wait_task_inactive(task_t * p);
#else
#define wait_task_inactive(p)	do { } while (0)
#endif

#define remove_parent(p)	list_del_init(&(p)->sibling)
#define add_parent(p, parent)	list_add_tail(&(p)->sibling,&(parent)->children)

/**
 * �����̴�������ɾ����
 */
#define REMOVE_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_del_init(&(p)->tasks);			\
	remove_parent(p);					\
	} while (0)

/**
 * �����̲��뵽���������С�
 * ����list_add_tail���뵽������β��;ֻ���������̲߳ż���������,����ֻ����parent��
 */
#define SET_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_add_tail(&(p)->tasks,&init_task.tasks);	\
	add_parent(p, (p)->parent);				\
	} while (0)

#define next_task(p)	list_entry((p)->tasks.next, struct task_struct, tasks)
#define prev_task(p)	list_entry((p)->tasks.prev, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

/*
 * Careful: do_each_thread/while_each_thread is a double loop so
 *          'break' will not work as expected - use goto instead.
 */
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

extern task_t * FASTCALL(next_thread(const task_t *p));

#define thread_group_leader(p)	(p->pid == p->tgid)

static inline int thread_group_empty(task_t *p)
{
	return list_empty(&p->pids[PIDTYPE_TGID].pid_list);
}

#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))

extern void unhash_process(struct task_struct *p);

/*
 * Protects ->fs, ->files, ->mm, ->ptrace, ->group_info, ->comm, keyring
 * subscriptions and synchronises with wait4().  Also used in procfs.
 *
 * Nests both inside and outside of read_lock(&tasklist_lock).
 * It must not be nested with write_lock_irq(&tasklist_lock),
 * neither inside nor outside.
 */
static inline void task_lock(struct task_struct *p)
{
	spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
	spin_unlock(&p->alloc_lock);
}

/* set thread flags in other task's structures
 * - see asm/thread_info.h for TIF_xxxx flags available
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(tsk->thread_info,flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(tsk->thread_info,flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

/**
 * �����������������ʾ�Ľ����з������Ĺ����źţ��ͷ���1�����򷵻�0��
 * �ú���ֻ��ͨ�������̵�TIF_SIGPENDING��־��
 */
static inline int signal_pending(struct task_struct *p)
{
	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}
  
static inline int need_resched(void)
{
	return unlikely(test_thread_flag(TIF_NEED_RESCHED));
}

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 * cond_resched_softirq() will enable bhs before scheduling.
 */
extern int cond_resched(void);
extern int cond_resched_lock(spinlock_t * lock);
extern int cond_resched_softirq(void);

/*
 * Does a critical section need to be broken due to another
 * task waiting?:
 */
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
# define need_lockbreak(lock) ((lock)->break_lock)
#else
# define need_lockbreak(lock) 0
#endif

/*
 * Does a critical section need to be broken due to another
 * task waiting or preemption being signalled:
 */
static inline int lock_need_resched(spinlock_t *lock)
{
	if (need_lockbreak(lock) || need_resched())
		return 1;
	return 0;
}

/* Reevaluate whether the task has signals pending delivery.
   This is required every time the blocked sigset_t changes.
   callers must hold sighand->siglock.  */

extern FASTCALL(void recalc_sigpending_tsk(struct task_struct *t));
extern void recalc_sigpending(void);

extern void signal_wake_up(struct task_struct *t, int resume_stopped);

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return p->thread_info->cpu;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
	p->thread_info->cpu = cpu;
}

#else

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return 0;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
}

#endif /* CONFIG_SMP */

#ifdef HAVE_ARCH_PICK_MMAP_LAYOUT
extern void arch_pick_mmap_layout(struct mm_struct *mm);
#else
static inline void arch_pick_mmap_layout(struct mm_struct *mm)
{
	mm->mmap_base = TASK_UNMAPPED_BASE;
	mm->get_unmapped_area = arch_get_unmapped_area;
	mm->unmap_area = arch_unmap_area;
}
#endif

extern long sched_setaffinity(pid_t pid, cpumask_t new_mask);
extern long sched_getaffinity(pid_t pid, cpumask_t *mask);

#ifdef CONFIG_MAGIC_SYSRQ

extern void normalize_rt_tasks(void);

#endif

/* try_to_freeze
 *
 * Checks whether we need to enter the refrigerator
 * and returns 1 if we did so.
 */
#ifdef CONFIG_PM
extern void refrigerator(unsigned long);
extern int freeze_processes(void);
extern void thaw_processes(void);

static inline int try_to_freeze(unsigned long refrigerator_flags)
{
	if (unlikely(current->flags & PF_FREEZE)) {
		refrigerator(refrigerator_flags);
		return 1;
	} else
		return 0;
}
#else
static inline void refrigerator(unsigned long flag) {}
static inline int freeze_processes(void) { BUG(); return 0; }
static inline void thaw_processes(void) {}

static inline int try_to_freeze(unsigned long refrigerator_flags)
{
	return 0;
}
#endif /* CONFIG_PM */
#endif /* __KERNEL__ */

#endif