/*
 *  linux/kernel/timer.c
 *
 *  Kernel internal timers, kernel timekeeping, basic process system calls
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-01-28  Modified by Finn Arne Gangstad to make timers scale better.
 *
 *  1997-09-10  Updated NTP code according to technical memorandum Jan '96
 *              "A Kernel Model for Precision Timekeeping" by Dave Mills
 *  1998-12-24  Fixed a xtime SMP race (we need the xtime_lock rw spinlock to
 *              serialize accesses to xtime/lost_ticks).
 *                              Copyright (C) 1998  Andrea Arcangeli
 *  1999-03-10  Improved NTP compatibility by Ulrich Windl
 *  2002-05-31	Move sys_sysinfo here and make its locking sane, Robert Love
 *  2000-10-05  Implemented scalable SMP per-CPU timer handling.
 *                              Copyright (C) 2000, 2001, 2002  Ingo Molnar
 *              Designed by David S. Miller, Alexey Kuznetsov and Ingo Molnar
 */

#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/notifier.h>
#include <linux/thread_info.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/div64.h>
#include <asm/timex.h>
#include <asm/io.h>

#ifdef CONFIG_TIME_INTERPOLATION
static void time_interpolator_update(long delta_nsec);
#else
#define time_interpolator_update(x)
#endif

/*
 * per-CPU timer vector definitions:
 */
#define TVN_BITS 6
#define TVR_BITS 8
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

typedef struct tvec_s {
	struct list_head vec[TVN_SIZE];
} tvec_t;

typedef struct tvec_root_s {
	struct list_head vec[TVR_SIZE];
} tvec_root_t;

/**
 * ÿ��CPU�ϵĶ�̬��ʱ��Ԫ��
 */
struct tvec_t_base_s {
	spinlock_t lock;
	/**
	 * ��Ҫ���Ķ�̬��ʱ�������絽��ʱ�䡣
	 * ������ֵ��jiffiesһ����˵�����ӳٺ���û�л�ѹ��
	 * ������ֵС��jiffies��˵��ǰ����������صĿ��ӳٺ������뱻����
	 * �ڳ�ʼ��ʱ������ֵ��jiffies��ȣ�Ȼ����run_timer_softieq������������ֵ��
	 * �����صĿ��ӳٺ����ܳ�һ��ʱ�䶼û�б�ִ��ʱ��timer_jiffies���ܻ������jiffies�ܶࡣ
	 */
	unsigned long timer_jiffies;
	/**
	 * �ڶ�CPU�ϣ�running_timerָ�򱾵�CPU��ǰ������Ķ�̬��ʱ����timer_list�ṹ��
	 */
	struct timer_list *running_timer;
	/**
	 * ������һ�����飬�����ڽ����ŵ�����255�������ڽ�Ҫ���ڵ����ж�̬��ʱ����
	 */
	tvec_root_t tv1;
	/**
	 * ������һ�����飬�����ڽ����ŵ�����2^14-1�������ڽ�Ҫ���ڵ����ж�̬��ʱ����
	 */
	tvec_t tv2;
	/**
	 * ������һ�����飬�����ڽ����ŵ�����2^20-1�������ڽ�Ҫ���ڵ����ж�̬��ʱ����
	 */
	tvec_t tv3;
	/**
	 * ������һ�����飬�����ڽ����ŵ�����2^26-1�������ڽ�Ҫ���ڵ����ж�̬��ʱ����
	 */
	tvec_t tv4;
	/**
	 * ������һ�����飬������һ�����expires�ڵ��ڵĶ�̬��ʱ����
	 */
	tvec_t tv5;
} ____cacheline_aligned_in_smp;

typedef struct tvec_t_base_s tvec_base_t;

static inline void set_running_timer(tvec_base_t *base,
					struct timer_list *timer)
{
#ifdef CONFIG_SMP
	base->running_timer = timer;
#endif
}

/* Fake initialization */
/**
 * ��̬��ʱ������Ҫ�ṹ��ÿ��Ԫ����һ��tvec_base_t����
 * ��������̬��ʱ����Ҫ���������ݡ�
 */
static DEFINE_PER_CPU(tvec_base_t, tvec_bases) = { SPIN_LOCK_UNLOCKED };

static void check_timer_failed(struct timer_list *timer)
{
	static int whine_count;
	if (whine_count < 16) {
		whine_count++;
		printk("Uninitialised timer!\n");
		printk("This is just a warning.  Your computer is OK\n");
		printk("function=0x%p, data=0x%lx\n",
			timer->function, timer->data);
		dump_stack();
	}
	/*
	 * Now fix it up
	 */
	spin_lock_init(&timer->lock);
	timer->magic = TIMER_MAGIC;
}

static inline void check_timer(struct timer_list *timer)
{
	if (timer->magic != TIMER_MAGIC)
		check_timer_failed(timer);
}


/*
 * ���ݶ�ʱ���ĵ�����ʱ�䣬��timer �ƶ���base �к��ʵ�λ����
 */
static void internal_add_timer(tvec_base_t *base, struct timer_list *timer)
{
	/*ȡ�õ��ڵ�ʣ��ʱ���*/
	unsigned long expires = timer->expires;
	unsigned long idx = expires - base->timer_jiffies;

	/*
	 * ���ݵ���ʱ�����㶨ʱ����Ҫ�����λ��vec 
	 * ����ʱ����2^8 tick �ڣ�����t1��vec
	 * ����ʱ���� 2^(8+6) ��tick �ڣ�����t2 ��vec
	 * ����ʱ���� 2^(8+2*6) ��tick �ڣ�����t3 ��vec
	 * ����ʱ���� 2^(8+3*6) ��tick �ڣ�����t4 ��vec
	 * ����ʱ���� 2^32  ��tick �ڣ�����t5 ��vec
	 * ����ʱ�䳬��2^32 ��tick ��, ��������ʱ��Ϊ2^32�η��󣬼���t5��vec
	 * �ѳ�������ʱ��ģ����뵽t1 ��
	 */
	struct list_head *vec;

	if (idx < TVR_SIZE) {
		int i = expires & TVR_MASK;
		vec = base->tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) { 
		int i = (expires >> TVR_BITS) & TVN_MASK;
		vec = base->tv2.vec + i;
	} else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = base->tv3.vec + i;
	} else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
		int i = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
		vec = base->tv4.vec + i;
	} else if ((signed long) idx < 0) {
		/*
		 * Can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
		vec = base->tv1.vec + (base->timer_jiffies & TVR_MASK);
	} else {
		int i;
		/* If the timeout is larger than 0xffffffff on 64-bit
		 * architectures then we use the maximum timeout:
		 */
		if (idx > 0xffffffffUL) {
			idx = 0xffffffffUL;
			expires = idx + base->timer_jiffies;
		}
		i = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
		vec = base->tv5.vec + i;
	}

	/*����ʱ�����뵽��Ӧλ�õ�vec ����*/
	/*
	 * Timers are FIFO:
	 */
	list_add_tail(&timer->entry, vec);
}

int __mod_timer(struct timer_list *timer, unsigned long expires)
{
	tvec_base_t *old_base, *new_base;
	unsigned long flags;
	int ret = 0;

	BUG_ON(!timer->function);

	check_timer(timer);

	spin_lock_irqsave(&timer->lock, flags);
	new_base = &__get_cpu_var(tvec_bases);
repeat:
	old_base = timer->base;

	/*
	 * Prevent deadlocks via ordering by old_base < new_base.
	 */
	if (old_base && (new_base != old_base)) {
		if (old_base < new_base) {
			spin_lock(&new_base->lock);
			spin_lock(&old_base->lock);
		} else {
			spin_lock(&old_base->lock);
			spin_lock(&new_base->lock);
		}
		/*
		 * The timer base might have been cancelled while we were
		 * trying to take the lock(s):
		 */
		if (timer->base != old_base) {
			spin_unlock(&new_base->lock);
			spin_unlock(&old_base->lock);
			goto repeat;
		}
	} else {
		spin_lock(&new_base->lock);
		if (timer->base != old_base) {
			spin_unlock(&new_base->lock);
			goto repeat;
		}
	}

	/*
	 * Delete the previous timeout (if there was any), and install
	 * the new one:
	 */
	if (old_base) {
		list_del(&timer->entry);
		ret = 1;
	}
	timer->expires = expires;
	internal_add_timer(new_base, timer);
	timer->base = new_base;

	if (old_base && (new_base != old_base))
		spin_unlock(&old_base->lock);
	spin_unlock(&new_base->lock);
	spin_unlock_irqrestore(&timer->lock, flags);

	return ret;
}

EXPORT_SYMBOL(__mod_timer);

/***
 * add_timer_on - start a timer on a particular CPU
 * @timer: the timer to be added
 * @cpu: the CPU to start it on
 *
 * This is not very scalable on SMP. Double adds are not possible.
 */
void add_timer_on(struct timer_list *timer, int cpu)
{
	tvec_base_t *base = &per_cpu(tvec_bases, cpu);
  	unsigned long flags;
  
  	BUG_ON(timer_pending(timer) || !timer->function);

	check_timer(timer);

	spin_lock_irqsave(&base->lock, flags);
	internal_add_timer(base, timer);
	timer->base = base;
	spin_unlock_irqrestore(&base->lock, flags);
}


/***
 * mod_timer - modify a timer's timeout
 * @timer: the timer to be modified
 *
 * mod_timer is a more efficient way to update the expire field of an
 * active timer (if the timer is inactive it will be activated)
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. mod_timer() of an inactive timer returns 0, mod_timer() of an
 * active timer returns 1.)
 */
/*
 * �����̬��ʱ���Ѿ������������У������mod_timer ����������
 * expires�ֶε�ֵ������Ҳ�ܽ�������뵽���ʵ�������
 */
int mod_timer(struct timer_list *timer, unsigned long expires)
{
	BUG_ON(!timer->function);

	check_timer(timer);

	/*
	 * This is a common optimization triggered by the
	 * networking code - if the timer is re-modified
	 * to be the same thing then just return:
	 */
	if (timer->expires == expires && timer_pending(timer))
		return 1;

	return __mod_timer(timer, expires);
}

EXPORT_SYMBOL(mod_timer);

/***
 * del_timer - deactive a timer.
 * @timer: the timer to be deactivated
 *
 * del_timer() deactivates a timer - this works on both active and inactive
 * timers.
 *
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. del_timer() of an inactive timer returns 0, del_timer() of an
 * active timer returns 1.)
 */
int del_timer(struct timer_list *timer)
{
	unsigned long flags;
	tvec_base_t *base;

	check_timer(timer);

repeat:
 	base = timer->base;
	if (!base)
		return 0;
	spin_lock_irqsave(&base->lock, flags);
	if (base != timer->base) {
		spin_unlock_irqrestore(&base->lock, flags);
		goto repeat;
	}
	list_del(&timer->entry);
	/* Need to make sure that anybody who sees a NULL base also sees the list ops */
	smp_wmb();
	timer->base = NULL;
	spin_unlock_irqrestore(&base->lock, flags);

	return 1;
}

EXPORT_SYMBOL(del_timer);

#ifdef CONFIG_SMP
/***
 * del_timer_sync - deactivate a timer and wait for the handler to finish.
 * @timer: the timer to be deactivated
 *
 * This function only differs from del_timer() on SMP: besides deactivating
 * the timer it also makes sure the handler has finished executing on other
 * CPUs.
 *
 * Synchronization rules: callers must prevent restarting of the timer,
 * otherwise this function is meaningless. It must not be called from
 * interrupt contexts. The caller must not hold locks which would prevent
 * completion of the timer's handler.  Upon exit the timer is not queued and
 * the handler is not running on any CPU.
 *
 * The function returns whether it has deactivated a pending timer or not.
 *
 * del_timer_sync() is slow and complicated because it copes with timer
 * handlers which re-arm the timer (periodic timers).  If the timer handler
 * is known to not do this (a single shot timer) then use
 * del_singleshot_timer_sync() instead.
 */
/*
 * ��������ɾ����ʱ����Ȼ����ö�ʱ�������Ƿ�������CPU
 * �����У�����ǣ��͵ȴ���ֱ����ʱ����������
 * ִ���ٶ�������Ϊ��Ҫ���Ƕ�ʱ���ἤ���Լ������
 */
int del_timer_sync(struct timer_list *timer)
{
	tvec_base_t *base;
	int i, ret = 0;

	check_timer(timer);

del_again:
	ret += del_timer(timer);

	for_each_online_cpu(i) {
		base = &per_cpu(tvec_bases, i);
		if (base->running_timer == timer) {
			while (base->running_timer == timer) {
				cpu_relax();
				preempt_check_resched();
			}
			break;
		}
	}
	smp_rmb();
	if (timer_pending(timer))
		goto del_again;

	return ret;
}
EXPORT_SYMBOL(del_timer_sync);

/***
 * del_singleshot_timer_sync - deactivate a non-recursive timer
 * @timer: the timer to be deactivated
 *
 * This function is an optimization of del_timer_sync for the case where the
 * caller can guarantee the timer does not reschedule itself in its timer
 * function.
 *
 * Synchronization rules: callers must prevent restarting of the timer,
 * otherwise this function is meaningless. It must not be called from
 * interrupt contexts. The caller must not hold locks which wold prevent
 * completion of the timer's handler.  Upon exit the timer is not queued and
 * the handler is not running on any CPU.
 *
 * The function returns whether it has deactivated a pending timer or not.
 */
/**
 * �Ӷ�ʱ��������ɾ��һ����ʱ��
 * ���������֪����ʱ�������Ӳ����¼��ʱ����ʹ�ñ������ٶȿ�
 */
int del_singleshot_timer_sync(struct timer_list *timer)
{
	int ret = del_timer(timer);

	if (!ret) {
		ret = del_timer_sync(timer);
		BUG_ON(ret);
	}

	return ret;
}
EXPORT_SYMBOL(del_singleshot_timer_sync);
#endif

/**
 * ��̬��ʱ���ֱ������������С�tv1��tv5,�ֱ𱣴�2^8,2^14,2^20,2^26,2^32��tick�ڵ���Ķ�ʱ��
 * ��tv1��Ϊ��ʱ������cascade����tv5->tv4->tv3->tv2->tv1
 * ���ǰѺ�һ�������еĶ�̬��ʱ�������ƶ�
 */
static int cascade(tvec_base_t *base, tvec_t *tv, int index)
{
	/* cascade all the timers from tv up one level */
	struct list_head *head, *curr;

	head = tv->vec + index;
	curr = head->next;
	/*
	 * We are removing _all_ timers from the list, so we don't  have to
	 * detach them individually, just clear the list afterwards.
	 */
	while (curr != head) {
		struct timer_list *tmp;

		tmp = list_entry(curr, struct timer_list, entry);
		BUG_ON(tmp->base != base);
		curr = curr->next;
		internal_add_timer(base, tmp);
	}
	INIT_LIST_HEAD(head);

	return index;
}

/***
 * __run_timers - run all expired timers (if any) on this CPU.
 * @base: the timer vector to be processed.
 *
 * This function cascades all vectors and executes all expired timer
 * vectors.
 */
#define INDEX(N) (base->timer_jiffies >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK

/**
 * ����CPU�Ķ�̬��ʱ���������ж���������ִ�С�
 */
static inline void __run_timers(tvec_base_t *base)
{
	struct timer_list *timer;

	/**
	 * ���base->lock ����������ֹ�����ж�
	 * ���ڽṹ������add_timer����mod_timer,del_timer�б����ʡ�
	 * ����ЩAPI���ṩ���ں˿������ã���֪�ں˿����߻Ὣ��������ʲô����
	 * ����ֻ����spin_lock_irq���ַ�ʽ�����ˡ�
	 * ��Ϊ�������ж���������ִ�У�����һ���ǿ��жϵģ����Բ��ر����жϣ�ǿ�غ�ǿ�������ˡ�
	 * ��Ȼǿ��ǿ���ж���һ�ֲ����µ���Ϊ��������ȴ���������⡣
	 */
	spin_lock_irq(&base->lock);
	/**
	 * ��ʼһ��while ѭ������base->timer_jiffies ����jiffies ��ֵʱ��ֹ
	 * ����jiffies��time_jiffies��ֵ������һ���ģ��������ѭ������ִֻ��һ�Ρ�
	 * ���ǣ������ִ�����ж�ʱ��������ʱ���жϣ���ô����������Ŀ��ܻᵽ���µĶ�̬��ʱ����
	 * ��ʱ�Ͳ�һ����ִֻ��һ���ˡ�
	 */
	while (time_after_eq(jiffies, base->timer_jiffies)) {
		struct list_head work_list = LIST_HEAD_INIT(work_list);
		struct list_head *head = &work_list;
		/**
		 * index��base->tv1����������ֵ������������һ�ν�Ҫ����Ķ�ʱ����
		 */
 		int index = base->timer_jiffies & TVR_MASK;
 
		/*
		 * Cascade timers:
		 */
		/**
		 * index == 0˵��tv1�����������Ѿ��������ˡ�ͨ��cascade�����˶�̬��ʱ����
		 * cascade��tv5->tv4->tv3->tv2->tv1
		 */
		/*
		 * base->timer_jiffies  �������絽��ʱ�䣬���û�л�ѹ��һ����ڵ�ǰʱ��jiffies
		 * ע��ֻ��Ų����ǰʱ���(base->timer_jiffies) ��Ӧ��vec Ԫ���ϵ�����
		 * ������vec Ԫ�صȵ���Ӧλ��(base->timer_jiffies) ����ʱ���ٴ����ƶ�, ������Ͳμ�<��������ں˼ܹ�>15.2С��
		 * index ==0 ����˵����ǰʱ����Ӧ��256 ��tick ����û��Ҫ����Ķ�ʱ��
		 * index == 0 ˵����δ�� 2^8  ��tick��û�е��ڵĶ�ʱ������ô��Ҫ����tv2-> tv1
		 * cascade(tv2) == 0 ˵����δ�� 2^14  ��tick��û�е��ڵĶ�ʱ������ô��Ҫ����tv3-> tv2
		 * cascade(tv3) == 0 ˵����δ�� 2^20  ��tick��û�е��ڵĶ�ʱ������ô��Ҫ����tv4-> tv3
		 * cascade(tv4) == 0 ˵����δ�� 2^26  ��tick��û�е��ڵĶ�ʱ������ô��Ҫ����tv5-> tv4
		 */		
		if (!index &&
			(!cascade(base, &base->tv2, INDEX(0))) &&
				(!cascade(base, &base->tv3, INDEX(1))) &&
					!cascade(base, &base->tv4, INDEX(2)))
			cascade(base, &base->tv5, INDEX(3));
		/**
		 * ����һ��ѭ�����ͽ�timer_jiffies������
		 */
		++base->timer_jiffies; 
		/**
		 * ��tv1.vec[indx]�еĶ�ʱ���ƶ���work_list�С�
		 * ����headָ��work_list��ͷ��
		 */
		list_splice_init(base->tv1.vec + index, &work_list);
repeat:
		/**
		 * ���������е�ÿһ����ʱ����
		 */
		if (!list_empty(head)) {
			void (*fn)(unsigned long);
			unsigned long data;

			/**
			 * ��������ȡ����ʱ����
			 */
			timer = list_entry(head->next,struct timer_list,entry);
 			fn = timer->function;
 			data = timer->data;

			/**
			 * ��������ɾ����ʱ����
			 */
			list_del(&timer->entry);
			/**
			 * ���õ�ǰCPU���ڴ���Ķ�ʱ������SMP ϵͳ��������
			 */
			set_running_timer(base, timer);
			smp_wmb();
			timer->base = NULL;
			/**
			 * ע�������÷����������Ķ�ʱ����������û�б����ص�������
			 */
			spin_unlock_irq(&base->lock);
			{
				u32 preempt_count = preempt_count();
				/*ִ�ж�ʱ������*/
				fn(data);
				/**
				 * ȷ���ڶ�ʱ�������У����������޸���ռ������
				 */
				if (preempt_count != preempt_count()) {
					printk("huh, entered %p with %08x, exited with %08x?\n", fn, preempt_count, preempt_count());
					BUG();
				}
			}
			spin_lock_irq(&base->lock);
			goto repeat;
		}
	}
	set_running_timer(base, NULL);
	spin_unlock_irq(&base->lock);
}

#ifdef CONFIG_NO_IDLE_HZ
/*
 * Find out when the next timer event is due to happen. This
 * is used on S/390 to stop all activity when a cpus is idle.
 * This functions needs to be called disabled.
 */
unsigned long next_timer_interrupt(void)
{
	tvec_base_t *base;
	struct list_head *list;
	struct timer_list *nte;
	unsigned long expires;
	tvec_t *varray[4];
	int i, j;

	base = &__get_cpu_var(tvec_bases);
	spin_lock(&base->lock);
	expires = base->timer_jiffies + (LONG_MAX >> 1);
	list = 0;

	/* Look for timer events in tv1. */
	j = base->timer_jiffies & TVR_MASK;
	do {
		list_for_each_entry(nte, base->tv1.vec + j, entry) {
			expires = nte->expires;
			if (j < (base->timer_jiffies & TVR_MASK))
				list = base->tv2.vec + (INDEX(0));
			goto found;
		}
		j = (j + 1) & TVR_MASK;
	} while (j != (base->timer_jiffies & TVR_MASK));

	/* Check tv2-tv5. */
	varray[0] = &base->tv2;
	varray[1] = &base->tv3;
	varray[2] = &base->tv4;
	varray[3] = &base->tv5;
	for (i = 0; i < 4; i++) {
		j = INDEX(i);
		do {
			if (list_empty(varray[i]->vec + j)) {
				j = (j + 1) & TVN_MASK;
				continue;
			}
			list_for_each_entry(nte, varray[i]->vec + j, entry)
				if (time_before(nte->expires, expires))
					expires = nte->expires;
			if (j < (INDEX(i)) && i < 3)
				list = varray[i + 1]->vec + (INDEX(i + 1));
			goto found;
		} while (j != (INDEX(i)));
	}
found:
	if (list) {
		/*
		 * The search wrapped. We need to look at the next list
		 * from next tv element that would cascade into tv element
		 * where we found the timer element.
		 */
		list_for_each_entry(nte, list, entry) {
			if (time_before(nte->expires, expires))
				expires = nte->expires;
		}
	}
	spin_unlock(&base->lock);
	return expires;
}
#endif

/******************************************************************/

/*
 * Timekeeping variables
 */
unsigned long tick_usec = TICK_USEC; 		/* USER_HZ period (usec) */
/**
 * ÿ��tick��nsֵ�������1000HZ�����ֵ����1000 * 1000
 * ��PC�ϣ�������ʼ����9999848����Ӧ��HzԼΪ1000.15Hz��
 * �����������ⲿʱ��ͬ���Ļ�������ֵ���ܱ��ں��Զ��������μ�adjtimex���ã�
 */
unsigned long tick_nsec = TICK_NSEC;		/* ACTHZ period (nsec) */

/* 
 * The current time 
 * wall_to_monotonic is what we need to add to xtime (or xtime corrected 
 * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
 * at zero at system boot time, so wall_to_monotonic will be negative,
 * however, we will ALWAYS keep the tv_nsec part positive so we can use
 * the usual normalization.
 */
struct timespec xtime __attribute__ ((aligned (16)));
struct timespec wall_to_monotonic __attribute__ ((aligned (16)));

EXPORT_SYMBOL(xtime);

/* Don't completely fail for HZ > 500.  */
int tickadj = 500/HZ ? : 1;		/* microsecs */


/*
 * phase-lock loop variables
 */
/* TIME_ERROR prevents overwriting the CMOS clock */
int time_state = TIME_OK;		/* clock synchronization status	*/
int time_status = STA_UNSYNC;		/* clock status bits		*/
long time_offset;			/* time adjustment (us)		*/
long time_constant = 2;			/* pll time constant		*/
long time_tolerance = MAXFREQ;		/* frequency tolerance (ppm)	*/
long time_precision = 1;		/* clock precision (us)		*/
long time_maxerror = NTP_PHASE_LIMIT;	/* maximum error (us)		*/
long time_esterror = NTP_PHASE_LIMIT;	/* estimated error (us)		*/
long time_phase;			/* phase offset (scaled us)	*/
long time_freq = (((NSEC_PER_SEC + HZ/2) % HZ - HZ/2) << SHIFT_USEC) / NSEC_PER_USEC;
					/* frequency offset (scaled ppm)*/
long time_adj;				/* tick adjust (scaled 1 / HZ)	*/
long time_reftime;			/* time at last adjustment (s)	*/
long time_adjust;
long time_next_adjust;

/*
 * this routine handles the overflow of the microsecond field
 *
 * The tricky bits of code to handle the accurate clock support
 * were provided by Dave Mills (Mills@UDEL.EDU) of NTP fame.
 * They were originally developed for SUN and DEC kernels.
 * All the kudos should go to Dave for this stuff.
 *
 */
static void second_overflow(void)
{
    long ltemp;

    /* Bump the maxerror field */
    time_maxerror += time_tolerance >> SHIFT_USEC;
    if ( time_maxerror > NTP_PHASE_LIMIT ) {
	time_maxerror = NTP_PHASE_LIMIT;
	time_status |= STA_UNSYNC;
    }

    /*
     * Leap second processing. If in leap-insert state at
     * the end of the day, the system clock is set back one
     * second; if in leap-delete state, the system clock is
     * set ahead one second. The microtime() routine or
     * external clock driver will insure that reported time
     * is always monotonic. The ugly divides should be
     * replaced.
     */
    switch (time_state) {

    case TIME_OK:
	if (time_status & STA_INS)
	    time_state = TIME_INS;
	else if (time_status & STA_DEL)
	    time_state = TIME_DEL;
	break;

    case TIME_INS:
	if (xtime.tv_sec % 86400 == 0) {
	    xtime.tv_sec--;
	    wall_to_monotonic.tv_sec++;
	    /* The timer interpolator will make time change gradually instead
	     * of an immediate jump by one second.
	     */
	    time_interpolator_update(-NSEC_PER_SEC);
	    time_state = TIME_OOP;
	    clock_was_set();
	    printk(KERN_NOTICE "Clock: inserting leap second 23:59:60 UTC\n");
	}
	break;

    case TIME_DEL:
	if ((xtime.tv_sec + 1) % 86400 == 0) {
	    xtime.tv_sec++;
	    wall_to_monotonic.tv_sec--;
	    /* Use of time interpolator for a gradual change of time */
	    time_interpolator_update(NSEC_PER_SEC);
	    time_state = TIME_WAIT;
	    clock_was_set();
	    printk(KERN_NOTICE "Clock: deleting leap second 23:59:59 UTC\n");
	}
	break;

    case TIME_OOP:
	time_state = TIME_WAIT;
	break;

    case TIME_WAIT:
	if (!(time_status & (STA_INS | STA_DEL)))
	    time_state = TIME_OK;
    }

    /*
     * Compute the phase adjustment for the next second. In
     * PLL mode, the offset is reduced by a fixed factor
     * times the time constant. In FLL mode the offset is
     * used directly. In either mode, the maximum phase
     * adjustment for each second is clamped so as to spread
     * the adjustment over not more than the number of
     * seconds between updates.
     */
    if (time_offset < 0) {
	ltemp = -time_offset;
	if (!(time_status & STA_FLL))
	    ltemp >>= SHIFT_KG + time_constant;
	if (ltemp > (MAXPHASE / MINSEC) << SHIFT_UPDATE)
	    ltemp = (MAXPHASE / MINSEC) << SHIFT_UPDATE;
	time_offset += ltemp;
	time_adj = -ltemp << (SHIFT_SCALE - SHIFT_HZ - SHIFT_UPDATE);
    } else {
	ltemp = time_offset;
	if (!(time_status & STA_FLL))
	    ltemp >>= SHIFT_KG + time_constant;
	if (ltemp > (MAXPHASE / MINSEC) << SHIFT_UPDATE)
	    ltemp = (MAXPHASE / MINSEC) << SHIFT_UPDATE;
	time_offset -= ltemp;
	time_adj = ltemp << (SHIFT_SCALE - SHIFT_HZ - SHIFT_UPDATE);
    }

    /*
     * Compute the frequency estimate and additional phase
     * adjustment due to frequency error for the next
     * second. When the PPS signal is engaged, gnaw on the
     * watchdog counter and update the frequency computed by
     * the pll and the PPS signal.
     */
    pps_valid++;
    if (pps_valid == PPS_VALID) {	/* PPS signal lost */
	pps_jitter = MAXTIME;
	pps_stabil = MAXFREQ;
	time_status &= ~(STA_PPSSIGNAL | STA_PPSJITTER |
			 STA_PPSWANDER | STA_PPSERROR);
    }
    ltemp = time_freq + pps_freq;
    if (ltemp < 0)
	time_adj -= -ltemp >>
	    (SHIFT_USEC + SHIFT_HZ - SHIFT_SCALE);
    else
	time_adj += ltemp >>
	    (SHIFT_USEC + SHIFT_HZ - SHIFT_SCALE);

#if HZ == 100
    /* Compensate for (HZ==100) != (1 << SHIFT_HZ).
     * Add 25% and 3.125% to get 128.125; => only 0.125% error (p. 14)
     */
    if (time_adj < 0)
	time_adj -= (-time_adj >> 2) + (-time_adj >> 5);
    else
	time_adj += (time_adj >> 2) + (time_adj >> 5);
#endif
#if HZ == 1000
    /* Compensate for (HZ==1000) != (1 << SHIFT_HZ).
     * Add 1.5625% and 0.78125% to get 1023.4375; => only 0.05% error (p. 14)
     */
    if (time_adj < 0)
	time_adj -= (-time_adj >> 6) + (-time_adj >> 7);
    else
	time_adj += (time_adj >> 6) + (time_adj >> 7);
#endif
}

/* in the NTP reference this is called "hardclock()" */
static void update_wall_time_one_tick(void)
{
	long time_adjust_step, delta_nsec;

	if ( (time_adjust_step = time_adjust) != 0 ) {
	    /* We are doing an adjtime thing. 
	     *
	     * Prepare time_adjust_step to be within bounds.
	     * Note that a positive time_adjust means we want the clock
	     * to run faster.
	     *
	     * Limit the amount of the step to be in the range
	     * -tickadj .. +tickadj
	     */
	     if (time_adjust > tickadj)
		time_adjust_step = tickadj;
	     else if (time_adjust < -tickadj)
		time_adjust_step = -tickadj;

	    /* Reduce by this step the amount of time left  */
	    time_adjust -= time_adjust_step;
	}
	delta_nsec = tick_nsec + time_adjust_step * 1000;
	/*
	 * Advance the phase, once it gets to one microsecond, then
	 * advance the tick more.
	 */
	time_phase += time_adj;
	if (time_phase <= -FINENSEC) {
		long ltemp = -time_phase >> (SHIFT_SCALE - 10);
		time_phase += ltemp << (SHIFT_SCALE - 10);
		delta_nsec -= ltemp;
	}
	else if (time_phase >= FINENSEC) {
		long ltemp = time_phase >> (SHIFT_SCALE - 10);
		time_phase -= ltemp << (SHIFT_SCALE - 10);
		delta_nsec += ltemp;
	}
	xtime.tv_nsec += delta_nsec;
	time_interpolator_update(delta_nsec);

	/* Changes by adjtime() do not take effect till next tick. */
	if (time_next_adjust != 0) {
		time_adjust = time_next_adjust;
		time_next_adjust = 0;
	}
}

/*
 * Using a loop looks inefficient, but "ticks" is
 * usually just one (we shouldn't be losing ticks,
 * we're doing this this way mainly for interrupt
 * latency reasons, not because we think we'll
 * have lots of lost timer ticks
 */
/*
 * ���ú���update_wall_time_one_tick �Σ�ÿ�ζ���xtime.tv_nsec ����1000000000
 * �����Ҫ�͸���xtime.tv_sec
 */

static void update_wall_time(unsigned long ticks)
{
	do {
		ticks--;
		update_wall_time_one_tick();
		if (xtime.tv_nsec >= 1000000000) {
			xtime.tv_nsec -= 1000000000;
			xtime.tv_sec++;
			second_overflow();
		}
	} while (ticks);
}

/*
 * Called from the timer interrupt handler to charge one tick to the current 
 * process.  user_tick is 1 if the tick is user time, 0 for system.
 */
/**
 * ����CPUͳ�Ƽ���
 */
void update_process_times(int user_tick)
{
	struct task_struct *p = current;
	int cpu = smp_processor_id();

	/* Note: this timer irq context must be accounted for as well. */
	/**
	 * ���������û�̬�����ں�̬�����˶೤ʱ�䡣
	 * �������������ʱ�䣬����ɱ�����̡�
	 */
	if (user_tick)
		account_user_time(p, jiffies_to_cputime(1));
	else
		account_system_time(p, HARDIRQ_OFFSET, jiffies_to_cputime(1));
	/**
	 * ����raise_softirq(TIMER_SOFTIRQ);�����CPU�ϵ�TIMER_SOFTIRQ
	 * ͨ���ں˺���add_timer��ӵĶ�ʱ������Ӧ��������������С�
	 * ���û��Ķ�ʱ����ͨ���ź���ʵ�ֵġ�
	 */
	run_local_timers();
	/**
	 * ���ϵͳ������һ����ֹ״̬����ô����tasklet_schedule�������CPU��
	 * rcu_tasklet����Ķ��С�����������ͷ�RCU��ص��ڴ档
	 */
	if (rcu_pending(cpu))
		rcu_check_callbacks(cpu, user_tick);
	/**
	 * scheduler_tickʹ��ǰ���̵�ʱ��Ƭ��������1��
	 */
	scheduler_tick();
}

/*
 * Nr of active tasks - counted in fixed-point numbers
 */
static unsigned long count_active_tasks(void)
{
	return (nr_running() + nr_uninterruptible()) * FIXED_1;
}

/*
 * Hmm.. Changed this, as the GNU make sources (load.c) seems to
 * imply that avenrun[] is the standard name for this kind of thing.
 * Nothing else seems to be standardized: the fractional size etc
 * all seem to differ on different machines.
 *
 * Requires xtime_lock to access.
 */
unsigned long avenrun[3];

/*
 * calc_load - given tick count, update the avenrun load estimates.
 * This is called while holding a write_lock on xtime_lock.
 */
/**
 * ��¼ϵͳ���أ��û�����uptime����ʱ�����ῴ����Щͳ��ֵ��
 * ƽ�����ذ�����TASK_RUNNING��TASK_UNINTERRUPT״̬�Ľ��̡����ڴ���TASK_UNINTERRUPT�Ľ����٣����Ը߸���һ����ζ��ϵͳ��æ��
 * ������Ҳ˵����ĳЩ����£��з������֡�
 * ��update_times��ÿ�����ĵ��á�
 */
static inline void calc_load(unsigned long ticks)
{
	unsigned long active_tasks; /* fixed-point */
	static int count = LOAD_FREQ;

	count -= ticks;
	if (count < 0) {
		count += LOAD_FREQ;
		active_tasks = count_active_tasks();
		CALC_LOAD(avenrun[0], EXP_1, active_tasks);
		CALC_LOAD(avenrun[1], EXP_5, active_tasks);
		CALC_LOAD(avenrun[2], EXP_15, active_tasks);
	}
}

/* jiffies at the most recent update of wall time */
/**
 * ǽ��ʱ�䡣��xtime��󱻸��µ�ʱ�䡣
 */
unsigned long wall_jiffies = INITIAL_JIFFIES;

/*
 * This read-write spinlock protects us from races in SMP while
 * playing with xtime and avenrun.
 */
#ifndef ARCH_HAVE_XTIME_LOCK
seqlock_t xtime_lock __cacheline_aligned_in_smp = SEQLOCK_UNLOCKED;

EXPORT_SYMBOL(xtime_lock);
#endif

/*
 * This function runs timers and the timer-tq in bottom half context.
 */
/**
 * TIMER_SOFTIRQ���ж�ִ���塣
 */
static void run_timer_softirq(struct softirq_action *h)
{
	/**
	 * ��CPU��ص�tvec_base_t�ṹȡ��base�С�
	 */
	tvec_base_t *base = &__get_cpu_var(tvec_bases);

	if (time_after_eq(jiffies, base->timer_jiffies))
		__run_timers(base);
}

/*
 * Called by the local, per-CPU timer interrupt on SMP.
 */
void run_local_timers(void)
{
	raise_softirq(TIMER_SOFTIRQ);
}

/*
 * Called by the timer interrupt. xtime_lock must already be taken
 * by the timer IRQ!
 */
/**
 * ����xtime��ֵ��������ϵͳ���ء�
 */
static inline void update_times(void)
{
	unsigned long ticks;

	/*
	 * ����jiffies ����һ��ʱ��wall_jiffies �Ĳ�ֵ
	 */
	ticks = jiffies - wall_jiffies;
	/**
	 * ticks��==0������
	 * �����п��ܵģ�wall_jiffies�����ܻ��������ط����޸ģ��Ӷ���jiffiesһ�¡�
	 */
	if (ticks) {
		/**
		 * һ����˵�������е�����������ô�͸���wall_jiffies�ɡ���
		 * ��ֵ��ǣ�ֱ����wall_jiffies = jiffies�������ˡ�
		 */
		wall_jiffies += ticks;
		/**
		 * ����xtime
		 */
		update_wall_time(ticks);
	}
	/**
	 * ���㸺��ƽ�⡣
	 */
	calc_load(ticks);
}
  
/*
 * The 64-bit jiffies value is not atomic - you MUST NOT read it
 * without sampling the sequence number in xtime_lock.
 * jiffies is defined in the linker script...
 */

/**
 * ��do_timer_interrupt���ã�ʱ���жϵ�һ���֡�
 */
void do_timer(struct pt_regs *regs)
{
	/**
	 * ֱ�Ӽ�jiffies_64�ǰ�ȫ�ģ���Ϊ��㺯��timer_interrupt��ʱ��Ȼ������xtime_lock˳������
	 */
	jiffies_64++;
	/**
	 * ����update_times����ϵͳ���ں�ʱ��,�����㵱ǰϵͳ���ء�
	 */
	update_times();
}

#ifdef __ARCH_WANT_SYS_ALARM

/*
 * For backwards compatibility?  This can be done in libc so Alpha
 * and all newer ports shouldn't need it.
 */
/*
 * alarm ϵͳ���õķ������̣�
 * ��ָ����ʱ�������̷���ITIMER_REAL �ź�
 * ��Ϊ������ITIMER_REAL ���͵Ķ�̬��ʱ��ʵ��
 * ���Բ��ܺ;���ITIMER_REAL ������setitimer() ϵͳ���ù�ͬʹ��
 */
asmlinkage unsigned long sys_alarm(unsigned int seconds)
{
	struct itimerval it_new, it_old;
	unsigned int oldalarm;

	it_new.it_interval.tv_sec = it_new.it_interval.tv_usec = 0;
	it_new.it_value.tv_sec = seconds;
	it_new.it_value.tv_usec = 0;
	do_setitimer(ITIMER_REAL, &it_new, &it_old);
	oldalarm = it_old.it_value.tv_sec;
	/* ehhh.. We can't return 0 if we have an alarm pending.. */
	/* And we'd better return too much than too little anyway */
	if ((!oldalarm && it_old.it_value.tv_usec) || it_old.it_value.tv_usec >= 500000)
		oldalarm++;
	return oldalarm;
}

#endif

#ifndef __alpha__

/*
 * The Alpha uses getxpid, getxuid, and getxgid instead.  Maybe this
 * should be moved into arch/i386 instead?
 */

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
asmlinkage long sys_getpid(void)
{
	return current->tgid;
}

/*
 * Accessing ->group_leader->real_parent is not SMP-safe, it could
 * change from under us. However, rather than getting any lock
 * we can use an optimistic algorithm: get the parent
 * pid, and go back and check that the parent is still
 * the same. If it has changed (which is extremely unlikely
 * indeed), we just try again..
 *
 * NOTE! This depends on the fact that even if we _do_
 * get an old value of "parent", we can happily dereference
 * the pointer (it was and remains a dereferencable kernel pointer
 * no matter what): we just can't necessarily trust the result
 * until we know that the parent pointer is valid.
 *
 * NOTE2: ->group_leader never changes from under us.
 */
asmlinkage long sys_getppid(void)
{
	int pid;
	struct task_struct *me = current;
	struct task_struct *parent;

	parent = me->group_leader->real_parent;
	for (;;) {
		pid = parent->tgid;
#ifdef CONFIG_SMP
{
		struct task_struct *old = parent;

		/*
		 * Make sure we read the pid before re-reading the
		 * parent pointer:
		 */
		rmb();
		parent = me->group_leader->real_parent;
		if (old != parent)
			continue;
}
#endif
		break;
	}
	return pid;
}

asmlinkage long sys_getuid(void)
{
	/* Only we change this so SMP safe */
	return current->uid;
}

asmlinkage long sys_geteuid(void)
{
	/* Only we change this so SMP safe */
	return current->euid;
}

asmlinkage long sys_getgid(void)
{
	/* Only we change this so SMP safe */
	return current->gid;
}

asmlinkage long sys_getegid(void)
{
	/* Only we change this so SMP safe */
	return  current->egid;
}

#endif

/*
 * ��ʱ�����ڣ�����ָ������
 */
static void process_timeout(unsigned long __data)
{
	wake_up_process((task_t *)__data);
}

/**
 * schedule_timeout - sleep until timeout
 * @timeout: timeout value in jiffies
 *
 * Make the current task sleep until @timeout jiffies have
 * elapsed. The routine will return immediately unless
 * the current task state has been set (see set_current_state()).
 *
 * You can set the task state as follows -
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout jiffies are guaranteed to
 * pass before the routine returns. The routine will return 0
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task. In this case the remaining time
 * in jiffies will be returned, or 0 if the timer expired in time
 *
 * The current task state is guaranteed to be TASK_RUNNING when this
 * routine returns.
 *
 * Specifying a @timeout value of %MAX_SCHEDULE_TIMEOUT will schedule
 * the CPU away without a bound on the timeout. In this case the return
 * value will be %MAX_SCHEDULE_TIMEOUT.
 *
 * In all cases the return value is guaranteed to be non-negative.
 */
fastcall signed long __sched schedule_timeout(signed long timeout)
{
	struct timer_list timer;
	unsigned long expire;

	switch (timeout)
	{
	case MAX_SCHEDULE_TIMEOUT:
		/*
		 * These two special cases are useful to be comfortable
		 * in the caller. Nothing more. We could take
		 * MAX_SCHEDULE_TIMEOUT from one of the negative value
		 * but I' d like to return a valid offset (>=0) to allow
		 * the caller to do everything it want with the retval.
		 */
		schedule();
		goto out;
	default:
		/*
		 * Another bit of PARANOID. Note that the retval will be
		 * 0 since no piece of kernel is supposed to do a check
		 * for a negative retval of schedule_timeout() (since it
		 * should never happens anyway). You just have the printk()
		 * that will tell you if something is gone wrong and where.
		 */
		if (timeout < 0)
		{
			printk(KERN_ERR "schedule_timeout: wrong timeout "
			       "value %lx from %p\n", timeout,
			       __builtin_return_address(0));
			current->state = TASK_RUNNING;
			goto out;
		}
	}

	expire = timeout + jiffies;

	init_timer(&timer);
	timer.expires = expire;
	timer.data = (unsigned long) current;
	timer.function = process_timeout;

	add_timer(&timer);
	/*���̹���ֱ����ʱ����ʱ*/
	schedule();
	/*�ָ�ʱɾ����ʱ��*/
	del_singleshot_timer_sync(&timer);

	timeout = expire - jiffies;

 out:
	return timeout < 0 ? 0 : timeout;
}

EXPORT_SYMBOL(schedule_timeout);

/* Thread ID - the internal kernel "pid" */
asmlinkage long sys_gettid(void)
{
	return current->pid;
}

static long __sched nanosleep_restart(struct restart_block *restart)
{
	unsigned long expire = restart->arg0, now = jiffies;
	struct timespec __user *rmtp = (struct timespec __user *) restart->arg1;
	long ret;

	/* Did it expire while we handled signals? */
	if (!time_after(expire, now))
		return 0;

	current->state = TASK_INTERRUPTIBLE;
	expire = schedule_timeout(expire - now);

	ret = 0;
	if (expire) {
		struct timespec t;
		jiffies_to_timespec(expire, &t);

		ret = -ERESTART_RESTARTBLOCK;
		if (rmtp && copy_to_user(rmtp, &t, sizeof(t)))
			ret = -EFAULT;
		/* The 'restart' block is already filled in */
	}
	return ret;
}

/**
 * nanosleepϵͳ���õķ������̡�
 * �����̹���ֱ��ָ����ʱ�������ꡣ
 */
asmlinkage long sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	struct timespec t;
	unsigned long expire;
	long ret;

	/**
	 * ���ȵ���copy_frome_user����ʳ��timerspec�ṹ�е�ֵ���Ƶ��ֲ�����t�С�
	 */
	if (copy_from_user(&t, rqtp, sizeof(t)))
		return -EFAULT;

	/**
	 * �ٶ���һ����Ч���ӳ١�
	 */
	if ((t.tv_nsec >= 1000000000L) || (t.tv_nsec < 0) || (t.tv_sec < 0))
		return -EINVAL;

	/**
	 * timespec_to_jiffies��t�е�ʱ����ת���ɽ�������
	 * �ټ���t.tv_sec || t.tv_nsec����Ϊ�˱��������
	 * ������������Ľ�����ʼ�ջᱻ��һ��
	 */
	expire = timespec_to_jiffies(&t) + (t.tv_sec || t.tv_nsec);
	/**
	 * schedule_timeout����ö�̬��ʱ����ʵ�ֽ��̵���ʱ��
	 */
	current->state = TASK_INTERRUPTIBLE;
	/**
	 * ���ܻ᷵��һ��ʣ���������
	 */
	expire = schedule_timeout(expire);

	ret = 0;
	/**
	 * schedule_timeout����һ��ʣ���������������ϵͳ���ñ��źŴ����(expire ��Ϊ0)��
	 * �ڴ��Զ�����ϵͳ���á�
	 */
	if (expire) {
		struct restart_block *restart;
		jiffies_to_timespec(expire, &t);
		if (rmtp && copy_to_user(rmtp, &t, sizeof(t)))
			return -EFAULT;

		restart = &current_thread_info()->restart_block;
		restart->fn = nanosleep_restart;
		restart->arg0 = jiffies + expire;
		restart->arg1 = (unsigned long) rmtp;
		/**
		 * ERESTART_RESTARTBLOCK��ʾϵͳ������Ҫ���������������ķ�ʽ���Ǽ򵥵�����ִ��ϵͳ���á�
		 * ����ִ��һ��ָ���ĺ���restart_block����ϵͳ������˯��һ��ʱ�䡣
		 */
		ret = -ERESTART_RESTARTBLOCK;
	}
	return ret;
}

/*
 * sys_sysinfo - fill in sysinfo struct
 */ 
asmlinkage long sys_sysinfo(struct sysinfo __user *info)
{
	struct sysinfo val;
	unsigned long mem_total, sav_total;
	unsigned int mem_unit, bitcount;
	unsigned long seq;

	memset((char *)&val, 0, sizeof(struct sysinfo));

	do {
		struct timespec tp;
		seq = read_seqbegin(&xtime_lock);

		/*
		 * This is annoying.  The below is the same thing
		 * posix_get_clock_monotonic() does, but it wants to
		 * take the lock which we want to cover the loads stuff
		 * too.
		 */

		getnstimeofday(&tp);
		tp.tv_sec += wall_to_monotonic.tv_sec;
		tp.tv_nsec += wall_to_monotonic.tv_nsec;
		if (tp.tv_nsec - NSEC_PER_SEC >= 0) {
			tp.tv_nsec = tp.tv_nsec - NSEC_PER_SEC;
			tp.tv_sec++;
		}
		val.uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

		val.loads[0] = avenrun[0] << (SI_LOAD_SHIFT - FSHIFT);
		val.loads[1] = avenrun[1] << (SI_LOAD_SHIFT - FSHIFT);
		val.loads[2] = avenrun[2] << (SI_LOAD_SHIFT - FSHIFT);

		val.procs = nr_threads;
	} while (read_seqretry(&xtime_lock, seq));

	si_meminfo(&val);
	si_swapinfo(&val);

	/*
	 * If the sum of all the available memory (i.e. ram + swap)
	 * is less than can be stored in a 32 bit unsigned long then
	 * we can be binary compatible with 2.2.x kernels.  If not,
	 * well, in that case 2.2.x was broken anyways...
	 *
	 *  -Erik Andersen <andersee@debian.org>
	 */

	mem_total = val.totalram + val.totalswap;
	if (mem_total < val.totalram || mem_total < val.totalswap)
		goto out;
	bitcount = 0;
	mem_unit = val.mem_unit;
	while (mem_unit > 1) {
		bitcount++;
		mem_unit >>= 1;
		sav_total = mem_total;
		mem_total <<= 1;
		if (mem_total < sav_total)
			goto out;
	}

	/*
	 * If mem_total did not overflow, multiply all memory values by
	 * val.mem_unit and set it to 1.  This leaves things compatible
	 * with 2.2.x, and also retains compatibility with earlier 2.4.x
	 * kernels...
	 */

	val.mem_unit = 1;
	val.totalram <<= bitcount;
	val.freeram <<= bitcount;
	val.sharedram <<= bitcount;
	val.bufferram <<= bitcount;
	val.totalswap <<= bitcount;
	val.freeswap <<= bitcount;
	val.totalhigh <<= bitcount;
	val.freehigh <<= bitcount;

 out:
	if (copy_to_user(info, &val, sizeof(struct sysinfo)))
		return -EFAULT;

	return 0;
}

static void __devinit init_timers_cpu(int cpu)
{
	int j;
	tvec_base_t *base;
       
	base = &per_cpu(tvec_bases, cpu);
	spin_lock_init(&base->lock);
	for (j = 0; j < TVN_SIZE; j++) {
		INIT_LIST_HEAD(base->tv5.vec + j);
		INIT_LIST_HEAD(base->tv4.vec + j);
		INIT_LIST_HEAD(base->tv3.vec + j);
		INIT_LIST_HEAD(base->tv2.vec + j);
	}
	for (j = 0; j < TVR_SIZE; j++)
		INIT_LIST_HEAD(base->tv1.vec + j);

	base->timer_jiffies = jiffies;
}

#ifdef CONFIG_HOTPLUG_CPU
static int migrate_timer_list(tvec_base_t *new_base, struct list_head *head)
{
	struct timer_list *timer;

	while (!list_empty(head)) {
		timer = list_entry(head->next, struct timer_list, entry);
		/* We're locking backwards from __mod_timer order here,
		   beware deadlock. */
		if (!spin_trylock(&timer->lock))
			return 0;
		list_del(&timer->entry);
		internal_add_timer(new_base, timer);
		timer->base = new_base;
		spin_unlock(&timer->lock);
	}
	return 1;
}

static void __devinit migrate_timers(int cpu)
{
	tvec_base_t *old_base;
	tvec_base_t *new_base;
	int i;

	BUG_ON(cpu_online(cpu));
	old_base = &per_cpu(tvec_bases, cpu);
	new_base = &get_cpu_var(tvec_bases);

	local_irq_disable();
again:
	/* Prevent deadlocks via ordering by old_base < new_base. */
	if (old_base < new_base) {
		spin_lock(&new_base->lock);
		spin_lock(&old_base->lock);
	} else {
		spin_lock(&old_base->lock);
		spin_lock(&new_base->lock);
	}

	if (old_base->running_timer)
		BUG();
	for (i = 0; i < TVR_SIZE; i++)
		if (!migrate_timer_list(new_base, old_base->tv1.vec + i))
			goto unlock_again;
	for (i = 0; i < TVN_SIZE; i++)
		if (!migrate_timer_list(new_base, old_base->tv2.vec + i)
		    || !migrate_timer_list(new_base, old_base->tv3.vec + i)
		    || !migrate_timer_list(new_base, old_base->tv4.vec + i)
		    || !migrate_timer_list(new_base, old_base->tv5.vec + i))
			goto unlock_again;
	spin_unlock(&old_base->lock);
	spin_unlock(&new_base->lock);
	local_irq_enable();
	put_cpu_var(tvec_bases);
	return;

unlock_again:
	/* Avoid deadlock with __mod_timer, by backing off. */
	spin_unlock(&old_base->lock);
	spin_unlock(&new_base->lock);
	cpu_relax();
	goto again;
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __devinit timer_cpu_notify(struct notifier_block *self, 
				unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	switch(action) {
	case CPU_UP_PREPARE:
		init_timers_cpu(cpu);
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_DEAD:
		migrate_timers(cpu);
		break;
#endif
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __devinitdata timers_nb = {
	.notifier_call	= timer_cpu_notify,
};


void __init init_timers(void)
{
	timer_cpu_notify(&timers_nb, (unsigned long)CPU_UP_PREPARE,
				(void *)(long)smp_processor_id());
	register_cpu_notifier(&timers_nb);
	open_softirq(TIMER_SOFTIRQ, run_timer_softirq, NULL);
}

#ifdef CONFIG_TIME_INTERPOLATION

struct time_interpolator *time_interpolator;
static struct time_interpolator *time_interpolator_list;
static DEFINE_SPINLOCK(time_interpolator_lock);

static inline u64 time_interpolator_get_cycles(unsigned int src)
{
	unsigned long (*x)(void);

	switch (src)
	{
		case TIME_SOURCE_FUNCTION:
			x = time_interpolator->addr;
			return x();

		case TIME_SOURCE_MMIO64	:
			return readq((void __iomem *) time_interpolator->addr);

		case TIME_SOURCE_MMIO32	:
			return readl((void __iomem *) time_interpolator->addr);

		default: return get_cycles();
	}
}

static inline u64 time_interpolator_get_counter(void)
{
	unsigned int src = time_interpolator->source;

	if (time_interpolator->jitter)
	{
		u64 lcycle;
		u64 now;

		do {
			lcycle = time_interpolator->last_cycle;
			now = time_interpolator_get_cycles(src);
			if (lcycle && time_after(lcycle, now))
				return lcycle;
			/* Keep track of the last timer value returned. The use of cmpxchg here
			 * will cause contention in an SMP environment.
			 */
		} while (unlikely(cmpxchg(&time_interpolator->last_cycle, lcycle, now) != lcycle));
		return now;
	}
	else
		return time_interpolator_get_cycles(src);
}

void time_interpolator_reset(void)
{
	time_interpolator->offset = 0;
	time_interpolator->last_counter = time_interpolator_get_counter();
}

#define GET_TI_NSECS(count,i) (((((count) - i->last_counter) & (i)->mask) * (i)->nsec_per_cyc) >> (i)->shift)

unsigned long time_interpolator_get_offset(void)
{
	/* If we do not have a time interpolator set up then just return zero */
	if (!time_interpolator)
		return 0;

	return time_interpolator->offset +
		GET_TI_NSECS(time_interpolator_get_counter(), time_interpolator);
}

#define INTERPOLATOR_ADJUST 65536
#define INTERPOLATOR_MAX_SKIP 10*INTERPOLATOR_ADJUST

static void time_interpolator_update(long delta_nsec)
{
	u64 counter;
	unsigned long offset;

	/* If there is no time interpolator set up then do nothing */
	if (!time_interpolator)
		return;

	/* The interpolator compensates for late ticks by accumulating
         * the late time in time_interpolator->offset. A tick earlier than
	 * expected will lead to a reset of the offset and a corresponding
	 * jump of the clock forward. Again this only works if the
	 * interpolator clock is running slightly slower than the regular clock
	 * and the tuning logic insures that.
         */

	counter = time_interpolator_get_counter();
	offset = time_interpolator->offset + GET_TI_NSECS(counter, time_interpolator);

	if (delta_nsec < 0 || (unsigned long) delta_nsec < offset)
		time_interpolator->offset = offset - delta_nsec;
	else {
		time_interpolator->skips++;
		time_interpolator->ns_skipped += delta_nsec - offset;
		time_interpolator->offset = 0;
	}
	time_interpolator->last_counter = counter;

	/* Tuning logic for time interpolator invoked every minute or so.
	 * Decrease interpolator clock speed if no skips occurred and an offset is carried.
	 * Increase interpolator clock speed if we skip too much time.
	 */
	if (jiffies % INTERPOLATOR_ADJUST == 0)
	{
		if (time_interpolator->skips == 0 && time_interpolator->offset > TICK_NSEC)
			time_interpolator->nsec_per_cyc--;
		if (time_interpolator->ns_skipped > INTERPOLATOR_MAX_SKIP && time_interpolator->offset == 0)
			time_interpolator->nsec_per_cyc++;
		time_interpolator->skips = 0;
		time_interpolator->ns_skipped = 0;
	}
}

static inline int
is_better_time_interpolator(struct time_interpolator *new)
{
	if (!time_interpolator)
		return 1;
	return new->frequency > 2*time_interpolator->frequency ||
	    (unsigned long)new->drift < (unsigned long)time_interpolator->drift;
}

void
register_time_interpolator(struct time_interpolator *ti)
{
	unsigned long flags;

	/* Sanity check */
	if (ti->frequency == 0 || ti->mask == 0)
		BUG();

	ti->nsec_per_cyc = ((u64)NSEC_PER_SEC << ti->shift) / ti->frequency;
	spin_lock(&time_interpolator_lock);
	write_seqlock_irqsave(&xtime_lock, flags);
	if (is_better_time_interpolator(ti)) {
		time_interpolator = ti;
		time_interpolator_reset();
	}
	write_sequnlock_irqrestore(&xtime_lock, flags);

	ti->next = time_interpolator_list;
	time_interpolator_list = ti;
	spin_unlock(&time_interpolator_lock);
}

void
unregister_time_interpolator(struct time_interpolator *ti)
{
	struct time_interpolator *curr, **prev;
	unsigned long flags;

	spin_lock(&time_interpolator_lock);
	prev = &time_interpolator_list;
	for (curr = *prev; curr; curr = curr->next) {
		if (curr == ti) {
			*prev = curr->next;
			break;
		}
		prev = &curr->next;
	}

	write_seqlock_irqsave(&xtime_lock, flags);
	if (ti == time_interpolator) {
		/* we lost the best time-interpolator: */
		time_interpolator = NULL;
		/* find the next-best interpolator */
		for (curr = time_interpolator_list; curr; curr = curr->next)
			if (is_better_time_interpolator(curr))
				time_interpolator = curr;
		time_interpolator_reset();
	}
	write_sequnlock_irqrestore(&xtime_lock, flags);
	spin_unlock(&time_interpolator_lock);
}
#endif /* CONFIG_TIME_INTERPOLATION */

/**
 * msleep - sleep safely even with waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
}

EXPORT_SYMBOL(msleep);

/**
 * msleep_interruptible - sleep waiting for waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
unsigned long msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout && !signal_pending(current)) {
		set_current_state(TASK_INTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
	return jiffies_to_msecs(timeout);
}

EXPORT_SYMBOL(msleep_interruptible);
