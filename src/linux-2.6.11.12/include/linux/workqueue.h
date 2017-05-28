/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>
#include <linux/linkage.h>
#include <linux/bitops.h>

struct workqueue_struct;

/**
 * ���������У�ÿ������������������
 */
struct work_struct {
	/**
	 * ��������Ѿ��ڹ������������У����ֶ�ֵ��Ϊ1������Ϊ0
	 */
	unsigned long pending;
	/**
	 * ָ�����������ǰһ�����һ��Ԫ�ص�ָ��
	 */
	struct list_head entry;
	/**
	 * �������ĵ�ַ
	 */
	void (*func)(void *);
	/**
	 * ���ݸ��������Ĳ���
	 */
	void *data;
	/**
	 * ͨ��ָ��cpu_workqueue_struct�ṹ
	 */
	void *wq_data;
	/**
	 * �����ӳٹ�����ִ�е���ʱ��
	 */
	struct timer_list timer;
};

#define __WORK_INITIALIZER(n, f, d) {				\
        .entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	.data = (d),						\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}

#define DECLARE_WORK(n, f, d)					\
	struct work_struct n = __WORK_INITIALIZER(n, f, d)

/*
 * initialize a work-struct's func and data pointers:
 */
#define PREPARE_WORK(_work, _func, _data)			\
	do {							\
		(_work)->func = _func;				\
		(_work)->data = _data;				\
	} while (0)

/*
 * initialize all of a work-struct:
 */
#define INIT_WORK(_work, _func, _data)				\
	do {							\
		INIT_LIST_HEAD(&(_work)->entry);		\
		(_work)->pending = 0;				\
		PREPARE_WORK((_work), (_func), (_data));	\
		init_timer(&(_work)->timer);			\
	} while (0)

extern struct workqueue_struct *__create_workqueue(const char *name,
						    int singlethread);

/**
 * ����һ���ַ�����Ϊ�����������´����������еĵ�ַ���ú���������n���������̡߳�
 * �����ݴ��ݸ��������ַ���Ϊ�������߳�������
 */
#define create_workqueue(name) __create_workqueue((name), 0)
/**
 * ��create_workqueue���ƣ����ǲ���ϵͳ���ж��ٸ�CPU����ֻ����һ���������̡߳�
 */
#define create_singlethread_workqueue(name) __create_workqueue((name), 1)

extern void destroy_workqueue(struct workqueue_struct *wq);

extern int FASTCALL(queue_work(struct workqueue_struct *wq, struct work_struct *work));
extern int FASTCALL(queue_delayed_work(struct workqueue_struct *wq, struct work_struct *work, unsigned long delay));
extern void FASTCALL(flush_workqueue(struct workqueue_struct *wq));

extern int FASTCALL(schedule_work(struct work_struct *work));
extern int FASTCALL(schedule_delayed_work(struct work_struct *work, unsigned long delay));

extern int schedule_delayed_work_on(int cpu, struct work_struct *work, unsigned long delay);
extern void flush_scheduled_work(void);
extern int current_is_keventd(void);
extern int keventd_up(void);

extern void init_workqueues(void);

/*
 * Kill off a pending schedule_delayed_work().  Note that the work callback
 * function may still be running on return from cancel_delayed_work().  Run
 * flush_scheduled_work() to wait on it.
 */
/**
 * queue_delayed_work������ʱ����work_struct���빤�����������С�
 * ���work_structĳ��ʱ��û�в�����У���ʱ����û�����У���cancel_delayed_work��ɾ������������к�����
 * xie.baoyouע��Ҳ����˵����ʱ������Ч�ˡ�
 */
static inline int cancel_delayed_work(struct work_struct *work)
{
	int ret;

	ret = del_timer_sync(&work->timer);
	if (ret)
		clear_bit(0, &work->pending);
	return ret;
}

#endif
