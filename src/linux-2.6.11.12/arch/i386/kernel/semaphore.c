/*
 * i386 semaphore implementation.
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Portions Copyright 1999 Red Hat, Inc.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 * rw semaphores implemented November 1999 by Benjamin LaHaise <bcrl@redhat.com>
 */
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/init.h>
#include <asm/semaphore.h>

/*
 * Semaphores are implemented using a two-way counter:
 * The "count" variable is decremented for each process
 * that tries to acquire the semaphore, while the "sleeping"
 * variable is a count of such acquires.
 *
 * Notably, the inline "up()" and "down()" functions can
 * efficiently test if they need to do any extra work (up
 * needs to do something only if count was negative before
 * the increment operation.
 *
 * "sleeping" and the contention routine ordering is protected
 * by the spinlock in the semaphore's waitqueue head.
 *
 * Note that these functions are only called when there is
 * contention on the lock, and as such all this is the
 * "non-critical" part of the whole semaphore business. The
 * critical part is the inline stuff in <asm/semaphore.h>
 * where we want to avoid any extra jumps and calls.
 */

/*
 * Logic:
 *  - only on a boundary condition do we need to care. When we go
 *    from a negative count to a non-negative, we wake people up.
 *  - when we go from a non-negative count to a negative do we
 *    (a) synchronize with the "sleeper" count and (b) make sure
 *    that we're on the wakeup list before we synchronize so that
 *    we cannot lose wakeup events.
 */

fastcall void __up(struct semaphore *sem)
{
	wake_up(&sem->wait);
}

/**
 * �������ź���ʧ��ʱ������__downʹ�̹߳���ֱ���ź������á�
 * �����ϣ������߳�����ΪTASK_UNINTERRUPTIBLE�������̷ŵ��ź����ĵȴ����С�
 */
fastcall void __sched __down(struct semaphore * sem)
{
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	unsigned long flags;

	/**
	 * ����״̬ΪTASK_UNINTERRUPTIBLE��
	 */
	tsk->state = TASK_UNINTERRUPTIBLE;
	/**
	 * �ڽ����̷ŵ��ȴ�����ǰ���Ȼ����������ֹ�����жϡ�
	 */
	spin_lock_irqsave(&sem->wait.lock, flags);
	/**
	 * �ȴ����е�__locked�汾�����ڵ��ú���ǰ�Ѿ��������������
	 * ��ע��ӵ��ȴ������ϵ�˯�߽����ǻ���ġ�����wakeup��໽��һ�����̡�
	 * ������Ѷ�����̣�������sleeper��count��ֵ����������ע���еĵ����������
	 */
	add_wait_queue_exclusive_locked(&sem->wait, &wait);

	/**
	 * sleepers��__down�����ľ��衣������׼ȷ�ģ�ͬʱ���Ǹ�Ч�ġ�
	 * �������Ǳ�ʾ�ڴ��ź�����˯�ߵ��߳�������������ʾ�Ƿ����߳����ź�������ȴ���
	 * ��ע������count�Ĺ�ϵ��
	 * ���ź�������ʱ����COUNT>=1��sleeper=0,��ʱ__down�������ᱻִ�С�
	 * ���ź���������ʱ��û��˯�ߵĽ��̣���count==0,sleeper==0
	 *     ��down�Ὣcount����Ϊ-1,�Ҵ�ʱsleeper==0�����뱾���������forѭ����
	 *     atomic_add_negativeִ��ԭ�Ӽӣ����Ǽӵ�ֵΪ0��atomic_add_negative��ɼ��countֵ�Ƿ�Ϊ����
	 *     ���Ϊ�����ͽ�sleeper������Ϊ1������˵���ź������ã��ͽ�sleeper����Ϊ0������ѭ���˳���
	 * ���ź���������ʱ�����������������ڵȴ�ʱ��count==-1��sleeper==1�������ʱ��count����1����count==-2,sleeper(��ʱ)==2
	 *     ��ʱatomic_add_negativeִ��ԭ�Ӽӣ���ʱ�ӵ�ֵ��sleeper-1��1.
	 *     ���Ҵ�ʱ�õ�����ʱ������linux�о�����Ҫ���������ݴ浽��ʱ�����У�ֻ����ʱ�����е�ֵ���ǿɿ��ġ������Ķ��п��ܱ������̻߳����жϸı䡣
	 *     ��sleeper-1����Ϊsem->sleepers++;һ��󣬵�atomic_add_negative���countǰ��count���ܱ��������̼���1�ˡ������Ϳ��Լ������������
	 *     �����1��countΪ����˵���ź���Ȼ�����ã���ʱcount���ָ���-1�ˣ����ס��down�н�count��1����ʱ��������ȥ����Ϊ�̲߳�û�л���ź�������count�����1
	 *     �����1��count��Ϊ������xie.baoyouע��Ӧ�þ���0����Ӧ������ֵ����Ҳ��sleeper������Ϊ0����������һ���̡߳�
	 *     ��ʱcount==0,sleeper==0���������Ǵ�ġ���ʵ����ȷ�ġ���Ϊ�½��̱������ˣ��½�������ʱ��sleeper==0����sleeper-1���൱���ǽ�count��ȥ1��
	 *     �½����ڵ���scheduleǰ����sleeper�����ó�1�ˡ�
	 */
	sem->sleepers++;
	for (;;) {
		int sleepers = sem->sleepers;

		/*
		 * Add "everybody else" into it. They aren't
		 * playing, because we own the spinlock in
		 * the wait_queue_head.
		 */
		if (!atomic_add_negative(sleepers - 1, &sem->count)) {
			sem->sleepers = 0;
			break;
		}
		sem->sleepers = 1;	/* us - see -1 above */
		spin_unlock_irqrestore(&sem->wait.lock, flags);

		schedule();

		spin_lock_irqsave(&sem->wait.lock, flags);
		tsk->state = TASK_UNINTERRUPTIBLE;
	}

	/**
	 * ��ע������ѭ���У�spin_lock_irqsave�����ʹ����������е�����ʱ��������ס�ġ�
	 * ���Կ��Ե���remove_wait_queue��locked�汾��
	 */
	remove_wait_queue_locked(&sem->wait, &wait);
	/**
	 * �ڻ���ź����󣬻���Ҫ���ѵȴ������ϵ���һ�����̡�ֻ������һ�����������Ƕ�����̡�
	 */
	wake_up_locked(&sem->wait);
	spin_unlock_irqrestore(&sem->wait.lock, flags);
	tsk->state = TASK_RUNNING;
}

/**
 * ��ͨ�������豸�����У������������жϷ������������жϡ�
 * ��˼�ǿ��Ա��ź��жϵ�down.���������ź����ϱ������Ľ��̱��źŴ�ϡ�
 * ����Ϻ����ڻ����Դǰ�����ѵĻ�����������count�ֶε�ֵ������-EINTR��
 * ���ԣ��豸������������жϷ���ֵ�����-EINTR���ͷ���IO������
 */
fastcall int __sched __down_interruptible(struct semaphore * sem)
{
	int retval = 0;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	unsigned long flags;

	tsk->state = TASK_INTERRUPTIBLE;
	spin_lock_irqsave(&sem->wait.lock, flags);
	add_wait_queue_exclusive_locked(&sem->wait, &wait);

	sem->sleepers++;
	for (;;) {
		int sleepers = sem->sleepers;

		/*
		 * With signals pending, this turns into
		 * the trylock failure case - we won't be
		 * sleeping, and we* can't get the lock as
		 * it has contention. Just correct the count
		 * and exit.
		 */
		if (signal_pending(current)) {
			retval = -EINTR;
			sem->sleepers = 0;
			atomic_add(sleepers, &sem->count);
			break;
		}

		/*
		 * Add "everybody else" into it. They aren't
		 * playing, because we own the spinlock in
		 * wait_queue_head. The "-1" is because we're
		 * still hoping to get the semaphore.
		 */
		if (!atomic_add_negative(sleepers - 1, &sem->count)) {
			sem->sleepers = 0;
			break;
		}
		sem->sleepers = 1;	/* us - see -1 above */
		spin_unlock_irqrestore(&sem->wait.lock, flags);

		schedule();

		spin_lock_irqsave(&sem->wait.lock, flags);
		tsk->state = TASK_INTERRUPTIBLE;
	}
	remove_wait_queue_locked(&sem->wait, &wait);
	wake_up_locked(&sem->wait);
	spin_unlock_irqrestore(&sem->wait.lock, flags);

	tsk->state = TASK_RUNNING;
	return retval;
}

/*
 * Trylock failed - make sure we correct for
 * having decremented the count.
 *
 * We could have done the trylock with a
 * single "cmpxchg" without failure cases,
 * but then it wouldn't work on a 386.
 */
/**
 * ֻ���쳣��������ϵͳ���÷�����򣬲ſ��Ե���down���жϴ������Ϳ��ӳٺ������ܵ���down����Ӧ����down_trylock��
 * ���ǵ������ǻ᲻������˯�ߡ�
 */
fastcall int __down_trylock(struct semaphore * sem)
{
	int sleepers;
	unsigned long flags;

	spin_lock_irqsave(&sem->wait.lock, flags);
	sleepers = sem->sleepers + 1;
	sem->sleepers = 0;

	/*
	 * Add "everybody else" and us into it. They aren't
	 * playing, because we own the spinlock in the
	 * wait_queue_head.
	 */
	if (!atomic_add_negative(sleepers, &sem->count)) {
		wake_up_locked(&sem->wait);
	}

	spin_unlock_irqrestore(&sem->wait.lock, flags);
	return 1;
}


/*
 * The semaphore operations have a special calling sequence that
 * allow us to do a simpler in-line version of them. These routines
 * need to convert that sequence back into the C sequence when
 * there is contention on the semaphore.
 *
 * %eax contains the semaphore pointer on entry. Save the C-clobbered
 * registers (%eax, %edx and %ecx) except %eax whish is either a return
 * value or just clobbered..
 */
asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed\n"
"__down_failed:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed_interruptible\n"
"__down_failed_interruptible:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down_interruptible\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __down_failed_trylock\n"
"__down_failed_trylock:\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"pushl %ebp\n\t"
	"movl  %esp,%ebp\n\t"
#endif
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __down_trylock\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
#if defined(CONFIG_FRAME_POINTER)
	"movl %ebp,%esp\n\t"
	"popl %ebp\n\t"
#endif
	"ret"
);

asm(
".section .sched.text\n"
".align 4\n"
".globl __up_wakeup\n"
"__up_wakeup:\n\t"
	"pushl %edx\n\t"
	"pushl %ecx\n\t"
	"call __up\n\t"
	"popl %ecx\n\t"
	"popl %edx\n\t"
	"ret"
);

/*
 * rw spinlock fallbacks
 */
#if defined(CONFIG_SMP)
asm(
".section .sched.text\n"
".align	4\n"
".globl	__write_lock_failed\n"
"__write_lock_failed:\n\t"
	LOCK "addl	$" RW_LOCK_BIAS_STR ",(%eax)\n"
"1:	rep; nop\n\t"
	"cmpl	$" RW_LOCK_BIAS_STR ",(%eax)\n\t"
	"jne	1b\n\t"
	LOCK "subl	$" RW_LOCK_BIAS_STR ",(%eax)\n\t"
	"jnz	__write_lock_failed\n\t"
	"ret"
);

/**
 * ���ں˽�ֹ��ռ�������������ʧ��ʱ�������е���������
 */
asm(
".section .sched.text\n"
".align	4\n"
".globl	__read_lock_failed\n"
"__read_lock_failed:\n\t"
	/**
	 * ��__build_read_lock_ptr�е�����subl��������һ��
	 * ��Ȼ��������ʧ���ˣ�����inc����������һ��
	 */
	LOCK "incl	(%eax)\n"
	/**
	 * �ٴ����꣬�˴���nop�ǲ������ٵġ���Ϊ�����������ߡ�
	 */
"1:	rep; nop\n\t"
	/**
	 * ѭ����ֱ��lockֵ�������
	 */
	"cmpl	$1,(%eax)\n\t"
	"js	1b\n\t"
	/**
	 * lockֵ�����������0�ˣ��ټ�1�������0,dec��lock�ֻ��ɸ�����
	 * ��ע��lockǰ׺���о���ʱ��lock��ֵ�����һ��Ʈ��������
	 */
	LOCK "decl	(%eax)\n\t"
	/**
	 * dec�󣬱�ɸ����ˣ�˵������һ���߳����ڱ��߳�ǰ��ռ����д�������ǻص�__read_lock_failed
	 * �������ret������������read_lock
	 */
	"js	__read_lock_failed\n\t"
	"ret"
);
#endif
