#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/mount.h>
#include <linux/sched.h>

/*
 * 进程的命名空间由进程描述符的namespace字段指向的namespace结构体描述
 */
struct namespace {
    /* 引用计数(共享命名空间的进程数)*/
	atomic_t		count;
	/* 命名空间根目录的已安装文件系统描述符，已安装文件系统由vfsmount结构描述 */
	struct vfsmount *	root;
	/* 所有已安装文件系统描述符链表的头 */
	struct list_head	list;
	/* 保护这个结构的读写信号量 */
	struct rw_semaphore	sem;
};

extern void umount_tree(struct vfsmount *);
extern int copy_namespace(int, struct task_struct *);
extern void __put_namespace(struct namespace *namespace);

static inline void put_namespace(struct namespace *namespace)
{
	if (atomic_dec_and_test(&namespace->count))
		__put_namespace(namespace);
}

/**
 * 从进程描述符中分离出与命名空间相关的数据结构。
 * 如果没有其他进程共享该结构，还删除所有这些数据结构。
 */
static inline void exit_namespace(struct task_struct *p)
{
	struct namespace *namespace = p->namespace;
	if (namespace) {
		task_lock(p);
		p->namespace = NULL;
		task_unlock(p);
		put_namespace(namespace);
	}
}

static inline void get_namespace(struct namespace *namespace)
{
	atomic_inc(&namespace->count);
}

#endif
#endif
