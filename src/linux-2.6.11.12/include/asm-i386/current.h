#ifndef _I386_CURRENT_H
#define _I386_CURRENT_H

#include <linux/thread_info.h>

struct task_struct;

static inline struct task_struct * get_current(void)
{
	return current_thread_info()->task;
}

/*
 * 为了获得当前在CPU上运行进程的描述符指针，内核要调用current宏
 */
#define current get_current()

#endif /* !(_I386_CURRENT_H) */
