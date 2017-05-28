#ifndef _LINUX_TTY_DRIVER_H
#define _LINUX_TTY_DRIVER_H

/*
 * This structure defines the interface between the low-level tty
 * driver and the tty routines.  The following routines can be
 * defined; unless noted otherwise, they are optional, and can be
 * filled in with a null pointer.
 *
 * int  (*open)(struct tty_struct * tty, struct file * filp);
 *
 * 	This routine is called when a particular tty device is opened.
 * 	This routine is mandatory; if this routine is not filled in,
 * 	the attempted open will fail with ENODEV.
 *     
 * void (*close)(struct tty_struct * tty, struct file * filp);
 *
 * 	This routine is called when a particular tty device is closed.
 *
 * int (*write)(struct tty_struct * tty,
 * 		 const unsigned char *buf, int count);
 *
 * 	This routine is called by the kernel to write a series of
 * 	characters to the tty device.  The characters may come from
 * 	user space or kernel space.  This routine will return the
 *	number of characters actually accepted for writing.  This
 *	routine is mandatory.
 *
 * void (*put_char)(struct tty_struct *tty, unsigned char ch);
 *
 * 	This routine is called by the kernel to write a single
 * 	character to the tty device.  If the kernel uses this routine,
 * 	it must call the flush_chars() routine (if defined) when it is
 * 	done stuffing characters into the driver.  If there is no room
 * 	in the queue, the character is ignored.
 *
 * void (*flush_chars)(struct tty_struct *tty);
 *
 * 	This routine is called by the kernel after it has written a
 * 	series of characters to the tty device using put_char().  
 * 
 * int  (*write_room)(struct tty_struct *tty);
 *
 * 	This routine returns the numbers of characters the tty driver
 * 	will accept for queuing to be written.  This number is subject
 * 	to change as output buffers get emptied, or if the output flow
 *	control is acted.
 * 
 * int  (*ioctl)(struct tty_struct *tty, struct file * file,
 * 	    unsigned int cmd, unsigned long arg);
 *
 * 	This routine allows the tty driver to implement
 *	device-specific ioctl's.  If the ioctl number passed in cmd
 * 	is not recognized by the driver, it should return ENOIOCTLCMD.
 * 
 * void (*set_termios)(struct tty_struct *tty, struct termios * old);
 *
 * 	This routine allows the tty driver to be notified when
 * 	device's termios settings have changed.  Note that a
 * 	well-designed tty driver should be prepared to accept the case
 * 	where old == NULL, and try to do something rational.
 *
 * void (*set_ldisc)(struct tty_struct *tty);
 *
 * 	This routine allows the tty driver to be notified when the
 * 	device's termios settings have changed.
 * 
 * void (*throttle)(struct tty_struct * tty);
 *
 * 	This routine notifies the tty driver that input buffers for
 * 	the line discipline are close to full, and it should somehow
 * 	signal that no more characters should be sent to the tty.
 * 
 * void (*unthrottle)(struct tty_struct * tty);
 *
 * 	This routine notifies the tty drivers that it should signals
 * 	that characters can now be sent to the tty without fear of
 * 	overrunning the input buffers of the line disciplines.
 * 
 * void (*stop)(struct tty_struct *tty);
 *
 * 	This routine notifies the tty driver that it should stop
 * 	outputting characters to the tty device.  
 * 
 * void (*start)(struct tty_struct *tty);
 *
 * 	This routine notifies the tty driver that it resume sending
 *	characters to the tty device.
 * 
 * void (*hangup)(struct tty_struct *tty);
 *
 * 	This routine notifies the tty driver that it should hangup the
 * 	tty device.
 *
 * void (*break_ctl)(struct tty_stuct *tty, int state);
 *
 * 	This optional routine requests the tty driver to turn on or
 * 	off BREAK status on the RS-232 port.  If state is -1,
 * 	then the BREAK status should be turned on; if state is 0, then
 * 	BREAK should be turned off.
 *
 * 	If this routine is implemented, the high-level tty driver will
 * 	handle the following ioctls: TCSBRK, TCSBRKP, TIOCSBRK,
 * 	TIOCCBRK.  Otherwise, these ioctls will be passed down to the
 * 	driver to handle.
 *
 * void (*wait_until_sent)(struct tty_struct *tty, int timeout);
 * 
 * 	This routine waits until the device has written out all of the
 * 	characters in its transmitter FIFO.
 *
 * void (*send_xchar)(struct tty_struct *tty, char ch);
 *
 * 	This routine is used to send a high-priority XON/XOFF
 * 	character to the device.
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/cdev.h>

struct tty_struct;

/**
 * tty�ص����������������ú���tty���ĵ��á�
 * Ŀǰ���ýṹ�����������к���ָ��Ҳ������tty_driver�С�
 */
struct tty_operations {
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	/**
	 * ����Ҫ���豸д�뵥���ַ�ʱ�����ô˺�����
	 * ���û��ʵ�ִ˺�����������write��
	 */
	void (*put_char)(struct tty_struct *tty, unsigned char ch);
	/**
	 * ��Ӳ���������ݡ�
	 */
	void (*flush_chars)(struct tty_struct *tty);
	/**
	 * ���ػ������е�ʣ��ռ䡣
	 */
	int  (*write_room)(struct tty_struct *tty);
	/**
	 * �������е��ַ�����
	 */
	int  (*chars_in_buffer)(struct tty_struct *tty);
	/**
	 * �����豸�ڵ����ioctlʱ���ú�����tty���ĵ��á�
	 */
	int  (*ioctl)(struct tty_struct *tty, struct file * file,
		    unsigned int cmd, unsigned long arg);
	/**
	 * ���豸��termios���÷����ı�ʱ����tty���ĵ��á�
	 */
	void (*set_termios)(struct tty_struct *tty, struct termios * old);
	/**
	 * ���ݿ��ƺ������������Ʋ���ֹtty���ĵ����뻺���������
	 * ��tty���ĵ����뻺��������ʱ�򣬵���throttle�����������豸��������ķ��͸�����ַ���
	 */
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	/**
	 * �����豸��
	 */
	void (*hangup)(struct tty_struct *tty);
	/**
	 * ����RS-232�˿ڵ�BREAK��·״̬��
	 */
	void (*break_ctl)(struct tty_struct *tty, int state);
	/**
	 * ˢ�»���������������ݽ�����ʧ��
	 */
	void (*flush_buffer)(struct tty_struct *tty);
	/**
	 * ����ʹ����·��̡�ͨ����������ʹ�á�
	 */
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	/**
	 * ����X�����ַ�������Ҫ���͵��ַ������ch�С�
	 */
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*read_proc)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
	int (*write_proc)(struct file *file, const char __user *buffer,
			  unsigned long count, void *data);
	/**
	 * ��á������ض�tty�豸��ǰ����·���á�
	 */
	int (*tiocmget)(struct tty_struct *tty, struct file *file);
	int (*tiocmset)(struct tty_struct *tty, struct file *file,
			unsigned int set, unsigned int clear);
};

/**
 * tty�豸��������
 */
struct tty_driver {
	/**
	 * ħ��ֵ��ΪTTY_DRIVER_MAGIC��
	 */
	int	magic;		/* magic number for this structure */
	struct cdev cdev;
	/**
	 * ��������ģ��������ߡ�
	 */
	struct module	*owner;
	/**
	 * ������������֡���/proc/tty��sysfs��ʹ�á�
	 */
	const char	*driver_name;
	const char	*devfs_name;
	/**
	 * ��������ڵ�����֡�
	 */
	const char	*name;
	/**
	 * �������豸ʱ����ʼʹ�õı�š�
	 */
	int	name_base;	/* offset of printed name */
	/**
	 * ������������豸�š�
	 */
	int	major;		/* major device number */
	/**
	 * ��ʼ���豸�š�ͨ����name_base��ͬ��Ĭ��Ϊ0.
	 */
	int	minor_start;	/* start of minor device number */
	/**
	 * ���Է��������������豸�ŵĸ�����
	 */
	int	minor_num;	/* number of *possible* devices */
	int	num;		/* number of devices allocated */
	/**
	 * tty�豸�������͡����ܵ�ֵΪ:TTY_DRIVER_TYPE_SYSTEM��TTY_DRIVER_TYPE_CONSOLE�ȡ�
	 */
	short	type;		/* type of tty driver */
	short	subtype;	/* subtype of tty driver */
	/**
	 * ��������ʱ�����г�ʼֵ�Ķ˿�ֵ��
	 */
	struct termios init_termios; /* Initial termios */
	int	flags;		/* tty driver flags */
	int	refcount;	/* for loadable tty drivers */
	/**
	 * �����������/proc��ڽṹ�塣
	 */
	struct proc_dir_entry *proc_entry; /* /proc fs entry */
	/**
	 * ָ��tty�����豸���������ָ�롣ֻ�ܱ�pty����ʹ�á�
	 */
	struct tty_driver *other; /* only used for the PTY driver */

	/*
	 * Pointer to the tty data structures
	 */
	struct tty_struct **ttys;
	struct termios **termios;
	struct termios **termios_locked;
	/**
	 * tty���������ڲ���״̬��ֻ�ܱ�pty����ʹ�á�
	 */
	void *driver_state;	/* only used for the PTY driver */
	
	/*
	 * Interface routines from the upper tty layer to the tty
	 * driver.	Will be replaced with struct tty_operations.
	 */
	/**
	 * ��tty�豸��
	 */
	int  (*open)(struct tty_struct * tty, struct file * filp);
	/**
	 * �ر�tty�豸��
	 */
	void (*close)(struct tty_struct * tty, struct file * filp);
	/**
	 * ���豸д�����ݡ����û�ж���put_char����ô����д�붼ͨ���˺�����
	 * ��ˣ����������û�ж���put_char����������⣬�������write����û��д���κ�һ���ַ�����
	 * ��ȷ��ÿ������д��һ���ַ���
	 */
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	/**
	 * ���豸д��һ���ַ�������س����з���
	 */
	void (*put_char)(struct tty_struct *tty, unsigned char ch);
	/**
	 * Ҫ�������������ݷ��͸�Ӳ����
	 */
	void (*flush_chars)(struct tty_struct *tty);
	/**
	 * ���ص�ǰ������������Ŀ��
	 */
	int  (*write_room)(struct tty_struct *tty);
	/**
	 * ����������ڷ����ڻ������л��ж��ٸ���Ҫ������ַ���
	 * �������Բ��ṩ�˺�����
	 */
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty, struct file * file,
		    unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct termios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	void (*break_ctl)(struct tty_struct *tty, int state);
	/**
	 * ��tty��������Ҫˢ������д�������е���������ʱ�����ô˺�����
	 */
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*read_proc)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
	int (*write_proc)(struct file *file, const char __user *buffer,
			  unsigned long count, void *data);
	int (*tiocmget)(struct tty_struct *tty, struct file *file);
	int (*tiocmset)(struct tty_struct *tty, struct file *file,
			unsigned int set, unsigned int clear);

	struct list_head tty_drivers;
};

extern struct list_head tty_drivers;

struct tty_driver *alloc_tty_driver(int lines);
void put_tty_driver(struct tty_driver *driver);
void tty_set_operations(struct tty_driver *driver, struct tty_operations *op);

/* tty driver magic number */
#define TTY_DRIVER_MAGIC		0x5402

/*
 * tty driver flags
 * 
 * TTY_DRIVER_RESET_TERMIOS --- requests the tty layer to reset the
 * 	termios setting when the last process has closed the device.
 * 	Used for PTY's, in particular.
 * 
 * TTY_DRIVER_REAL_RAW --- if set, indicates that the driver will
 * 	guarantee never not to set any special character handling
 * 	flags if ((IGNBRK || (!BRKINT && !PARMRK)) && (IGNPAR ||
 * 	!INPCK)).  That is, if there is no reason for the driver to
 * 	send notifications of parity and break characters up to the
 * 	line driver, it won't do so.  This allows the line driver to
 *	optimize for this case if this flag is set.  (Note that there
 * 	is also a promise, if the above case is true, not to signal
 * 	overruns, either.)
 *
 * TTY_DRIVER_NO_DEVFS --- if set, do not create devfs entries. This
 *	is only used by tty_register_driver().
 *
 * TTY_DRIVER_DEVPTS_MEM -- don't use the standard arrays, instead
 *	use dynamic memory keyed through the devpts filesystem.  This
 *	is only applicable to the pty driver.
 */
/**
 * ��tty�������ã���ʾ�����Ƿ��Ѿ�����װ��
 */
#define TTY_DRIVER_INSTALLED		0x0001
/**
 * �����ô˱�־�󣬻������һ�����̹ر��豸ʱ��tty���ĶԶ˿����ø�λ��
 */
#define TTY_DRIVER_RESET_TERMIOS	0x0002
/**
 * ��ʾtty��������ʹ����żУ������ж��ַ��̹߳�̡�
 * ��ʹ����·�������������ķ�ʽ�����ַ�����Ϊ�����ؼ���tty��������������յ�ÿһ���ַ���
 * ͨ�����ø�λ��
 */
#define TTY_DRIVER_REAL_RAW		0x0004
/**
 * ���Ĳ���ҪΪtty�������򴴽��κ�devfs��ڡ�
 * �������Ҫ��̬������ɾ�����豸������������˵�ǳ����á�
 */
#define TTY_DRIVER_NO_DEVFS		0x0008
#define TTY_DRIVER_DEVPTS_MEM		0x0010

/* tty driver types */
#define TTY_DRIVER_TYPE_SYSTEM		0x0001
#define TTY_DRIVER_TYPE_CONSOLE		0x0002
#define TTY_DRIVER_TYPE_SERIAL		0x0003
#define TTY_DRIVER_TYPE_PTY		0x0004
#define TTY_DRIVER_TYPE_SCC		0x0005	/* scc driver */
#define TTY_DRIVER_TYPE_SYSCONS		0x0006

/* system subtypes (magic, used by tty_io.c) */
#define SYSTEM_TYPE_TTY			0x0001
#define SYSTEM_TYPE_CONSOLE		0x0002
#define SYSTEM_TYPE_SYSCONS		0x0003
#define SYSTEM_TYPE_SYSPTMX		0x0004

/* pty subtypes (magic, used by tty_io.c) */
#define PTY_TYPE_MASTER			0x0001
#define PTY_TYPE_SLAVE			0x0002

/* serial subtype definitions */
#define SERIAL_TYPE_NORMAL	1

#endif /* #ifdef _LINUX_TTY_DRIVER_H */
