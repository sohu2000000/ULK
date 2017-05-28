#ifndef _LINUX_PID_H
#define _LINUX_PID_H

enum pid_type
{
	PIDTYPE_PID,    /*pid��     ���̵�PID*/
	PIDTYPE_TGID,   /*tgid��    �߳�����ͷ���̵�PID*/
	PIDTYPE_PGID,   /*pgrp:     ��������ͷ���̵�PID*/
	PIDTYPE_SID,    /*session:  �Ự��ͷ���̵�PID*/
	PIDTYPE_MAX
};

struct pid
{
	/* Try to keep pid_chain in the same cacheline as nr for find_pid */
	/**
	 * PIDֵ��
	 */
	int nr;
	/**
	 * ����ɢ�б�����һ����ǰһ��Ԫ�ء�
	 */
	struct hlist_node pid_chain;
	/* list of pids with the same nr, only one of them is in the hash */
	/**
	 * ÿ��PID�Ľ�������ͷ��
	 */
	struct list_head pid_list;
};

#define pid_task(elem, type) \
	list_entry(elem, struct task_struct, pids[type].pid_list)

/*
 * attach_pid() and detach_pid() must be called with the tasklist_lock
 * write-held.
 */
extern int FASTCALL(attach_pid(struct task_struct *task, enum pid_type type, int nr));

extern void FASTCALL(detach_pid(struct task_struct *task, enum pid_type));

/*
 * look up a PID in the hash table. Must be called with the tasklist_lock
 * held.
 */
extern struct pid *FASTCALL(find_pid(enum pid_type, int));

extern int alloc_pidmap(void);
extern void FASTCALL(free_pidmap(int));
extern void switch_exec_pids(struct task_struct *leader, struct task_struct *thread);

/**
 * ���do-whileѭ���Ŀ�ʼ�ͽ���
 * ѭ��������������PIDֵ����who��PID�����ϣ�����������ÿ����㱾��Ҳ��һ������������PID��ͬ���߳��飩
 * ��������Ϊtype,taskָ��ǰ��ɨ���Ԫ�صĽ�����������
 */
#define do_each_task_pid(who, type, task)				\
	if ((task = find_task_by_pid_type(type, who))) {		\
		prefetch((task)->pids[type].pid_list.next);		\
		do {

#define while_each_task_pid(who, type, task)				\
		} while (task = pid_task((task)->pids[type].pid_list.next,\
						type),			\
			prefetch((task)->pids[type].pid_list.next),	\
			hlist_unhashed(&(task)->pids[type].pid_chain));	\
	}								\

#endif /* _LINUX_PID_H */
