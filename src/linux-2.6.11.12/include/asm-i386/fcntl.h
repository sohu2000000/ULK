#ifndef _I386_FCNTL_H
#define _I386_FCNTL_H

/* open/fcntl - O_SYNC is only implemented on blocks devices and on files
   located on an ext2 file system */
#define O_ACCMODE	   0003
#define O_RDONLY	     00/* ֻ�� */
#define O_WRONLY	     01/* ֻд */
#define O_RDWR		     02/* ��д */
#define O_CREAT		   0100	/* �������򴴽� *//* not fcntl */
#define O_EXCL		   0200	/* ��O_CREAT��־������ļ����ڣ���ʧ�� *//* not fcntl */
#define O_NOCTTY	   0400	/* �Ӳ����ļ����������ն� *//* not fcntl */
#define O_TRUNC		  01000	/* �ض��ļ���ɾ���������� *//* not fcntl */
#define O_APPEND	  02000/* ���ļ�ĩβ��ʼд */
#define O_NONBLOCK	  04000/* �������� */
#define O_NDELAY	O_NONBLOCK
#define O_SYNC		 010000/* ͬ��д */
#define FASYNC		 020000	/* ͨ���źŷ���IO�¼�ͨ�� *//* fcntl, for BSD compatibility */
#define O_DIRECT	 040000	/* ֱ��IO *//* direct disk access hint */
#define O_LARGEFILE	0100000/* �����ļ�����С����2G */
#define O_DIRECTORY	0200000/* ����ļ�����Ŀ¼����ʧ�� */	/* must be a directory */
#define O_NOFOLLOW	0400000 /* ������·����ĩβ�ķ������� *//* don't follow links */
#define O_NOATIME	01000000/* �����������ڵ�ķ���ʱ�� */

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	8	/*  for sockets. */
#define F_GETOWN	9	/*  for sockets. */
#define F_SETSIG	10	/*  for sockets. */
#define F_GETSIG	11	/*  for sockets. */

#define F_GETLK64	12	/*  using 'struct flock64' */
#define F_SETLK64	13
#define F_SETLKW64	14

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

/* for old implementation of bsd flock () */
#define F_EXLCK		4	/* or 3 */
#define F_SHLCK		8	/* or 4 */

/* for leases */
#define F_INPROGRESS	16

/* operations for bsd flock(), also used by the kernel implementation */
/**
 * ����һ�����������
 */
#define LOCK_SH		1	/* shared lock */
/**
 * ����һ������������д����
 */
#define LOCK_EX		2	/* exclusive lock */
/**
 * �������ļ���ʱ����������������뵽�����������ء�
 */
#define LOCK_NB		4	/* or'd with one of the above to prevent
				   blocking */
/**
 * �ͷ��ļ�Ȱ������
 */
#define LOCK_UN		8	/* remove lock */

#define LOCK_MAND	32	/* This is a mandatory flock */
#define LOCK_READ	64	/* ... Which allows concurrent read operations */
#define LOCK_WRITE	128	/* ... Which allows concurrent write operations */
#define LOCK_RW		192	/* ... Which allows concurrent read & write ops */

/**
 * �û�̬����FL_POSIX��ʱ�����ں˴��ݵĲ�����
 */
struct flock {
	/**
	 * ��������
	 */
	short l_type;
	/**
	 * ��ʲô�ط���ʼ������
	 */
	short l_whence;
	/**
	 * �����ƫ����
	 */
	off_t l_start;
	/**
	 * ��������ĳ��ȡ�
	 */
	off_t l_len;
	/**
	 * ӵ���ߵ�PID
	 */
	pid_t l_pid;
};

struct flock64 {
	short  l_type;
	short  l_whence;
	loff_t l_start;
	loff_t l_len;
	pid_t  l_pid;
};

#define F_LINUX_SPECIFIC_BASE	1024

#endif
