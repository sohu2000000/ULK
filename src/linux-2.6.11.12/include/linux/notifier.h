/*
 *	Routines to manage notifier chains for passing status changes to any
 *	interested routines. We need this instead of hard coded call lists so
 *	that modules can poke their nose into the innards. The network devices
 *	needed them so here they are for the rest of you.
 *
 *				Alan Cox <Alan.Cox@linux.org>
 */
 
#ifndef _LINUX_NOTIFIER_H
#define _LINUX_NOTIFIER_H
#include <linux/errno.h>

/**
 * ֪ͨ�����㡣
 */
struct notifier_block
{
	/**
	 * ��Ҫִ�еĺ���
	 */
	int (*notifier_call)(struct notifier_block *self, unsigned long, void *);
	/**
	 * ָ����һ����ָ��
	 */
	struct notifier_block *next;
	/**
	 * �������ȼ������ǣ���ʵ�ʵĴ����У�����ע��Ľڵ㲻������priority������ʹ��Ĭ�ϵ� 0��
	 * �����ζ�ţ��ڵ��ִ��˳������ע���˳��
	 */
	int priority;
};


#ifdef __KERNEL__

extern int notifier_chain_register(struct notifier_block **list, struct notifier_block *n);
extern int notifier_chain_unregister(struct notifier_block **nl, struct notifier_block *n);
extern int notifier_call_chain(struct notifier_block **n, unsigned long val, void *v);

/**
 * �����֪ͨ������Ȥ
 */
#define NOTIFY_DONE		0x0000		/* Don't care */
/**
 * ֪ͨ����ɹ�
 */
#define NOTIFY_OK		0x0001		/* Suits me */
/**
 * notifier_call_chain�����������ȷ����ֹͣ���������Ǽ�����
 */
#define NOTIFY_STOP_MASK	0x8000		/* Don't call further */
/**
 * �д�������ֹͣ�Ե�ǰ�¼��Ĵ��� 
 */
#define NOTIFY_BAD		(NOTIFY_STOP_MASK|0x0002)	/* Bad/Veto action	*/
/*
 * Clean way to return from the notifier and stop further calls.
 */
/**
 * �ص�����������ˣ�����Ļص����������ᱻ���á�
 */
#define NOTIFY_STOP		(NOTIFY_OK|NOTIFY_STOP_MASK)

/*
 *	Declared notifiers so far. I can imagine quite a few more chains
 *	over time (eg laptop power reset chains, reboot chain (to clean 
 *	device units up), device [un]mount chain, module load/unload chain,
 *	low memory chain, screenblank chain (for plug in modular screenblankers) 
 *	VC switch chains (for loadable kernel svgalib VC switch helpers) etc...
 */
 
/* netdevice notifier chain */
/**
 * �������Ա����豸ʹ�ܡ�����dev_open������
 */
#define NETDEV_UP	0x0001	/* For now you can't veto a device up/down */
/**
 * NETDEV_GOING_DOWN�������Ա��潫����ֹ����NETDEV_DOWN�����������豸�ѱ���ֹ�����߾���dev_close������
 */
#define NETDEV_DOWN	0x0002
/**
 * �豸����Ӳ�������������Ŀǰ���ã�����
 */
#define NETDEV_REBOOT	0x0003	/* Tell a protocol stack a network interface
				   detected a hardware crash and restarted
				   - we can use this eg to kick tcp sessions
				   once done */
/**
 * �豸״̬���豸���øı䣬�ⱻ���ڸ�������������� NETDEV_CHANGEADDR ��NETDEV_CHANGENAME���Ρ�
 * ������dev->flags��־�ı�ʱ��
 */
#define NETDEV_CHANGE	0x0004	/* Notify device state change */
/**
 * �豸�Ѿ�ע�ᣬ�¼���register_netdevice����
 */
#define NETDEV_REGISTER 0x0005
/**
 * �豸��ע�����¼���unregister_netdevice����
 */
#define NETDEV_UNREGISTER	0x0006
#define NETDEV_CHANGEMTU	0x0007
/**
 * �豸Ӳ����ַ(��������Ĺ㲥��ַ)�Ѹı䡣
 */
#define NETDEV_CHANGEADDR	0x0008
/**
 * NETDEV_GOING_DOWN�������Ա��潫����ֹ����NETDEV_DOWN�����������豸�ѱ���ֹ�����߾���dev_close������
 */
#define NETDEV_GOING_DOWN	0x0009
/**
 * �豸�����ָı�
 */
#define NETDEV_CHANGENAME	0x000A

#define SYS_DOWN	0x0001	/* Notify of system down */
#define SYS_RESTART	SYS_DOWN
#define SYS_HALT	0x0002	/* Notify of system halt */
#define SYS_POWER_OFF	0x0003	/* Notify of system power off */

#define NETLINK_URELEASE	0x0001	/* Unicast netlink socket released */

#define CPU_ONLINE		0x0002 /* CPU (unsigned)v is up */
#define CPU_UP_PREPARE		0x0003 /* CPU (unsigned)v coming up */
#define CPU_UP_CANCELED		0x0004 /* CPU (unsigned)v NOT coming up */
#define CPU_DOWN_PREPARE	0x0005 /* CPU (unsigned)v going down */
#define CPU_DOWN_FAILED		0x0006 /* CPU (unsigned)v NOT going down */
#define CPU_DEAD		0x0007 /* CPU (unsigned)v dead */

#endif /* __KERNEL__ */
#endif /* _LINUX_NOTIFIER_H */
