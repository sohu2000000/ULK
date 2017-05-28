#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

/*
 * Resource limits
 */

/* Allow arch to control resource order */
#ifndef __ARCH_RLIMIT_ORDER
/**
 * ����ʹ��CPU���ʱ��(����Ϊ��λ)��������̳�����������ơ��ں˾�������һ��SIGXCPU�źš�
 * ������̻�����ֹ���ٷ�һ��SIGKILL�źš�
 */
#define RLIMIT_CPU		0	/* CPU time in ms */
/**
 * �ļ���С�����ֵ(���ֽ�Ϊ��λ)�����������ͼ��һ���ļ��Ĵ�С���䵽�������ֵ���ں˾͸�������̷�SIGXFS�źš�
 */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
/**
 * �Ѵ�С�����ֵ(���ֽ�Ϊ��λ)����������̵Ķ�֮ǰ���ں˼�����ֵ��
 */
#define RLIMIT_DATA		2	/* max data size */
/**
 * ջ��С�����ֵ(���ֽ�Ϊ��λ)���ں���������̵��û�̬��ջ֮ǰ������ֵ��
 */
#define RLIMIT_STACK		3	/* max stack size */
/**
 * �ڴ���Ϣת���ļ��Ĵ�С(���ֽ�Ϊ��λ)����һ�������쳣��ֹʱ���ں��ڽ��̵ĵ�ǰĿ¼��
 * �����ڴ���Ϣת���ļ�֮ǰ������ֵ��������ֵ��Ϊ0,�ں˾Ͳ������ļ���
 */
#define RLIMIT_CORE		4	/* max core file size */
/**
 * ������ӵ�е�ҳ���������Ŀǰ�Ƿ�ǿ�Ƶġ�
 */
#define RLIMIT_RSS		5	/* max resident set size */
/**
 * �û���ӵ�еĽ����������
 */
#define RLIMIT_NPROC		6	/* max number of processes */
/**
 * ���ļ����������������
 * ����һ�����ļ�����һ���ļ�������ʱ���ں˼�����ֵ��
 */
#define RLIMIT_NOFILE		7	/* max number of open files */
/**
 * �ǽ����ڴ�����ֵ(���ֽ�Ϊ��λ)��
 * ��������ͼͨ��mlloc��mlockallϵͳ������סһ��ҳ��ʱ���ں˼�����ֵ��
 */
#define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
/**
 * ���̵�ַ�ռ�������(���ֽ�Ϊ��λ)��������ʹ��malloc����غ����������ĵ�ַ�ռ�ʱ���ں˼�����ֵ��
 */ 
#define RLIMIT_AS		9	/* address space limit */
/**
 * �ļ��������ֵ��Ŀǰ�Ƿ�ǿ�Ƶġ�
 */
#define RLIMIT_LOCKS		10	/* maximum file locks held */
/**
 * ���̹����źŵ��������
 */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
/**
 * POSIX��Ϣ�����е�����ֽ�����
 */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */

#define RLIM_NLIMITS		13
#endif

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 */
#ifndef RLIM_INFINITY
#define RLIM_INFINITY	(~0UL)
#endif

#ifndef _STK_LIM_MAX
#define _STK_LIM_MAX	RLIM_INFINITY
#endif

#ifdef __KERNEL__

#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_DATA]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {      _STK_LIM, _STK_LIM_MAX  },	\
	[RLIMIT_CORE]		= {             0, RLIM_INFINITY },	\
	[RLIMIT_RSS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {             0,             0 },	\
	[RLIMIT_NOFILE]		= {      INR_OPEN,     INR_OPEN  },	\
	[RLIMIT_MEMLOCK]	= {   MLOCK_LIMIT,   MLOCK_LIMIT },	\
	[RLIMIT_AS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= { RLIM_INFINITY, RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { MAX_SIGPENDING, MAX_SIGPENDING },	\
	[RLIMIT_MSGQUEUE]	= { MQ_BYTES_MAX, MQ_BYTES_MAX },	\
}

#endif	/* __KERNEL__ */

#endif
