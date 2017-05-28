/*
 * 	NET3	Protocol independent device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Derived from the non IP parts of dev.c 1.0.19
 * 		Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *				Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *				Mark Evans, <evansmp@uhura.aston.ac.uk>
 *
 *	Additional Authors:
 *		Florian la Roche <rzsfl@rz.uni-sb.de>
 *		Alan Cox <gw4pts@gw4pts.ampr.org>
 *		David Hinds <dahinds@users.sourceforge.net>
 *		Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *		Adam Sulmicki <adam@cfar.umd.edu>
 *              Pekka Riikonen <priikone@poesidon.pspt.fi>
 *
 *	Changes:
 *              D.J. Barrow     :       Fixed bug where dev->refcnt gets set
 *              			to 2 if register_netdev gets called
 *              			before net_dev_init & also removed a
 *              			few lines of code in the process.
 *		Alan Cox	:	device private ioctl copies fields back.
 *		Alan Cox	:	Transmit queue code does relevant
 *					stunts to keep the queue safe.
 *		Alan Cox	:	Fixed double lock.
 *		Alan Cox	:	Fixed promisc NULL pointer trap
 *		????????	:	Support the full private ioctl range
 *		Alan Cox	:	Moved ioctl permission check into
 *					drivers
 *		Tim Kordas	:	SIOCADDMULTI/SIOCDELMULTI
 *		Alan Cox	:	100 backlog just doesn't cut it when
 *					you start doing multicast video 8)
 *		Alan Cox	:	Rewrote net_bh and list manager.
 *		Alan Cox	: 	Fix ETH_P_ALL echoback lengths.
 *		Alan Cox	:	Took out transmit every packet pass
 *					Saved a few bytes in the ioctl handler
 *		Alan Cox	:	Network driver sets packet type before
 *					calling netif_rx. Saves a function
 *					call a packet.
 *		Alan Cox	:	Hashed net_bh()
 *		Richard Kooijman:	Timestamp fixes.
 *		Alan Cox	:	Wrong field in SIOCGIFDSTADDR
 *		Alan Cox	:	Device lock protection.
 *		Alan Cox	: 	Fixed nasty side effect of device close
 *					changes.
 *		Rudi Cilibrasi	:	Pass the right thing to
 *					set_mac_address()
 *		Dave Miller	:	32bit quantity for the device lock to
 *					make it work out on a Sparc.
 *		Bjorn Ekwall	:	Added KERNELD hack.
 *		Alan Cox	:	Cleaned up the backlog initialise.
 *		Craig Metz	:	SIOCGIFCONF fix if space for under
 *					1 device.
 *	    Thomas Bogendoerfer :	Return ENODEV for dev_open, if there
 *					is no device open function.
 *		Andi Kleen	:	Fix error reporting for SIOCGIFCONF
 *	    Michael Chastain	:	Fix signed/unsigned for SIOCGIFCONF
 *		Cyrus Durgin	:	Cleaned for KMOD
 *		Adam Sulmicki   :	Bug Fix : Network Device Unload
 *					A network device unload needs to purge
 *					the backlog queue.
 *	Paul Rusty Russell	:	SIOCSIFNAME
 *              Pekka Riikonen  :	Netdev boot-time settings code
 *              Andrew Morton   :       Make unregister_netdevice wait
 *              			indefinitely on dev->refcnt
 * 		J Hadi Salim	:	- Backlog queue sampling
 *				        - netif_rx() feedback
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/config.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/if_bridge.h>
#include <linux/divert.h>
#include <net/dst.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#ifdef CONFIG_NET_RADIO
#include <linux/wireless.h>		/* Note : will define WIRELESS_EXT */
#include <net/iw_handler.h>
#endif	/* CONFIG_NET_RADIO */
#include <asm/current.h>

/* This define, if set, will randomly drop a packet when congestion
 * is more than moderate.  It helps fairness in the multi-interface
 * case when one of them is a hog, but it kills performance for the
 * single interface case so it is off now by default.
 */
#undef RAND_LIE

/* Setting this will sample the queue lengths and thus congestion
 * via a timer instead of as each packet is received.
 */
#undef OFFLINE_SAMPLE

/*
 *	The list of packet types we will receive (as opposed to discard)
 *	and the routines to invoke.
 *
 *	Why 16. Because with 16 the only overlap we get on a hash of the
 *	low nibble of the protocol value is RARP/SNAP/X.25.
 *
 *      NOTE:  That is no longer true with the addition of VLAN tags.  Not
 *             sure which should go first, but I bet it won't make much
 *             difference if we are running VLANs.  The good news is that
 *             this protocol won't be in the list unless compiled in, so
 *             the average user (w/out VLANs) will not be adversly affected.
 *             --BLG
 *
 *		0800	IP
 *		8100    802.1Q VLAN
 *		0001	802.3
 *		0002	AX.25
 *		0004	802.2
 *		8035	RARP
 *		0005	SNAP
 *		0805	X.25
 *		0806	ARP
 *		8137	IPX
 *		0009	Localtalk
 *		86DD	IPv6
 */

static DEFINE_SPINLOCK(ptype_lock);
static struct list_head ptype_base[16];	/* 16 way hashed list */
static struct list_head ptype_all;		/* Taps */

#ifdef OFFLINE_SAMPLE
static void sample_queue(unsigned long dummy);
static struct timer_list samp_timer = TIMER_INITIALIZER(sample_queue, 0, 0);
#endif

/*
 * The @dev_base list is protected by @dev_base_lock and the rtln
 * semaphore.
 *
 * Pure readers hold dev_base_lock for reading.
 *
 * Writers must hold the rtnl semaphore while they loop through the
 * dev_base list, and hold dev_base_lock for writing when they do the
 * actual updates.  This allows pure readers to access the list even
 * while a writer is preparing to update it.
 *
 * To put it another way, dev_base_lock is held for writing only to
 * protect against pure readers; the rtnl semaphore provides the
 * protection against other writers.
 *
 * See, for example usages, register_netdevice() and
 * unregister_netdevice(), which must be called with the rtnl
 * semaphore held.
 */
/**
 * �����豸�� net_device �ṹ������һ��ȫ�������У������ͷָ���� dev_base��
 */
struct net_device *dev_base;
static struct net_device **dev_tail = &dev_base;
DEFINE_RWLOCK(dev_base_lock);

EXPORT_SYMBOL(dev_base);
EXPORT_SYMBOL(dev_base_lock);

#define NETDEV_HASHBITS	8
/**
 * ���豸��Ϊ�����Ĺ�ϣ�����ǳ����ã��磬���� ioctl �ӿڸı�һ������ʱ��
 * ���ڵ����ù���ͨ��ioctl�ӿ����ں˽�����ͨ��ͨ���豸���������豸�� 
 */
static struct hlist_head dev_name_head[1<<NETDEV_HASHBITS];
/**
 * �������豸 ID��dev->ifindex Ϊ�����Ĺ�ϣ���������� net_device �ṹͨ��Ҫô�洢�豸 ID��Ҫô�洢 net_device �ṹ��ָ�롣
 * dev_index_head ���������κ����ã��µ�IP���ù���(���� IPROUTE2��)ͨ�� Netlink�׽��ֺ��ں˽�����ͨ��ͨ���豸ID�����豸��
 */
static struct hlist_head dev_index_head[1<<NETDEV_HASHBITS];

static inline struct hlist_head *dev_name_hash(const char *name)
{
	unsigned hash = full_name_hash(name, strnlen(name, IFNAMSIZ));
	return &dev_name_head[hash & ((1<<NETDEV_HASHBITS)-1)];
}

static inline struct hlist_head *dev_index_hash(int ifindex)
{
	return &dev_index_head[ifindex & ((1<<NETDEV_HASHBITS)-1)];
}

/*
 *	Our notifier list
 */
/**
 * �����豸״̬�ı�ʱ����֪ͨ��
 */
static struct notifier_block *netdev_chain;

/*
 *	Device drivers call our routines to queue packets here. We empty the
 *	queue in the local softnet handler.
 */
DEFINE_PER_CPU(struct softnet_data, softnet_data) = { 0, };

#ifdef CONFIG_SYSFS
extern int netdev_sysfs_init(void);
extern int netdev_register_sysfs(struct net_device *);
extern void netdev_unregister_sysfs(struct net_device *);
#else
#define netdev_sysfs_init()	 	(0)
#define netdev_register_sysfs(dev)	(0)
#define	netdev_unregister_sysfs(dev)	do { } while(0)
#endif


/*******************************************************************************

		Protocol management and registration routines

*******************************************************************************/

/*
 *	For efficiency
 */
/**
 * netdev_nit��ʾETH_P_ALLЭ��������
 */
int netdev_nit;

/*
 *	Add a protocol ID to the list. Now that the input handler is
 *	smarter we can dispense with all the messy stuff that used to be
 *	here.
 *
 *	BEWARE!!! Protocol handlers, mangling input packets,
 *	MUST BE last in hash buckets and checking protocol handlers
 *	MUST start from promiscuous ptype_all chain in net_bh.
 *	It is true now, do not change it.
 *	Explanation follows: if protocol handler, mangling packet, will
 *	be the first on list, it is not able to sense, that packet
 *	is cloned and should be copied-on-write, so that it will
 *	change it and subsequent readers will get broken packet.
 *							--ANK (980803)
 */

/**
 *	dev_add_pack - add packet handler
 *	@pt: packet type declaration
 *
 *	Add a protocol handler to the networking stack. The passed &packet_type
 *	is linked into kernel lists and may not be freed until it has been
 *	removed from the kernel lists.
 *
 *	This call does not sleep therefore it can not 
 *	guarantee all CPU's that are in middle of receiving packets
 *	will see the new packet type (until the next received packet).
 */

/**
 * ע��һ������Э�鴦������
 */
void dev_add_pack(struct packet_type *pt)
{
	int hash;

	spin_lock_bh(&ptype_lock);
	/**
	 * Ҫ��ӵĺ����Ƿ���һ��Э����̽��(pt_type == htons(ETH_P_ALL))
	 */
	if (pt->type == htons(ETH_P_ALL)) {
		/**
		 * ����ע���Э����̽������(netdev_nit++)
		 */
		netdev_nit++;
		/**
		 * �������ptype_all����
		 */
		list_add_rcu(&pt->list, &ptype_all);
	} else {
		/**
		 * �������뵽��ptype_baseָ���16�������е�һ����������뵽�ĸ���������������hashֵ
		 */
		hash = ntohs(pt->type) & 15;
		list_add_rcu(&pt->list, &ptype_base[hash]);
	}
	spin_unlock_bh(&ptype_lock);
}

extern void linkwatch_run_queue(void);



/**
 *	__dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns. 
 *
 *      The packet type might still be in use by receivers
 *	and must not be freed until after all the CPU's have gone
 *	through a quiescent state.
 */
void __dev_remove_pack(struct packet_type *pt)
{
	struct list_head *head;
	struct packet_type *pt1;

	spin_lock_bh(&ptype_lock);

	if (pt->type == htons(ETH_P_ALL)) {
		netdev_nit--;
		head = &ptype_all;
	} else
		head = &ptype_base[ntohs(pt->type) & 15];

	list_for_each_entry(pt1, head, list) {
		if (pt == pt1) {
			list_del_rcu(&pt->list);
			goto out;
		}
	}

	printk(KERN_WARNING "dev_remove_pack: %p not found.\n", pt);
out:
	spin_unlock_bh(&ptype_lock);
}
/**
 *	dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns.
 *
 *	This call sleeps to guarantee that no CPU is looking at the packet
 *	type after return.
 */
/**
 * �Ƴ�Э�鴦������
 */
void dev_remove_pack(struct packet_type *pt)
{
	/**
	 * ��ptype_all����ptype_base��ɾ��packet_type���ݽṹ��
	 */
	__dev_remove_pack(pt);

	/**
	 * Synchronize_net����ȷ����dev_remove_pack��������ʱ��û��һ���ط����ڶ�packet_type���ݽṹ�������á�
	 */
	synchronize_net();
}

/******************************************************************************

		      Device Boot-time Settings Routines

*******************************************************************************/

/* Boot time configuration table */
static struct netdev_boot_setup dev_boot_setup[NETDEV_BOOT_SETUP_MAX];

/**
 *	netdev_boot_setup_add	- add new setup entry
 *	@name: name of the device
 *	@map: configured settings for the device
 *
 *	Adds new setup entry to the dev_boot_setup list.  The function
 *	returns 0 on error and 1 on success.  This is a generic routine to
 *	all netdevices.
 */
static int netdev_boot_setup_add(char *name, struct ifmap *map)
{
	struct netdev_boot_setup *s;
	int i;

	s = dev_boot_setup;
	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] == '\0' || s[i].name[0] == ' ') {
			memset(s[i].name, 0, sizeof(s[i].name));
			strcpy(s[i].name, name);
			memcpy(&s[i].map, map, sizeof(s[i].map));
			break;
		}
	}

	return i >= NETDEV_BOOT_SETUP_MAX ? 0 : 1;
}

/**
 *	netdev_boot_setup_check	- check boot time settings
 *	@dev: the netdevice
 *
 * 	Check boot time settings for the device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found, 1 if they are.
 */
/**
 * �����׶ν���ʱ������������� netdev_boot_setup_check �����������Ľӿ��Ƿ�������ʱ�����й������� dev_boot_setup �����в���ʱ�����豸�� dev->name
 */
int netdev_boot_setup_check(struct net_device *dev)
{
	struct netdev_boot_setup *s = dev_boot_setup;
	int i;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] != '\0' && s[i].name[0] != ' ' &&
		    !strncmp(dev->name, s[i].name, strlen(s[i].name))) {
			dev->irq 	= s[i].map.irq;
			dev->base_addr 	= s[i].map.base_addr;
			dev->mem_start 	= s[i].map.mem_start;
			dev->mem_end 	= s[i].map.mem_end;
			return 1;
		}
	}
	return 0;
}


/**
 *	netdev_boot_base	- get address from boot time settings
 *	@prefix: prefix for network device
 *	@unit: id for network device
 *
 * 	Check boot time settings for the base address of device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found.
 */
unsigned long netdev_boot_base(const char *prefix, int unit)
{
	const struct netdev_boot_setup *s = dev_boot_setup;
	char name[IFNAMSIZ];
	int i;

	sprintf(name, "%s%d", prefix, unit);

	/*
	 * If device already registered then return base of 1
	 * to indicate not to probe for this interface
	 */
	if (__dev_get_by_name(name))
		return 1;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++)
		if (!strcmp(name, s[i].name))
			return s[i].map.base_addr;
	return 0;
}

/*
 * Saves at boot time configured settings for any netdevice.
 */
int __init netdev_boot_setup(char *str)
{
	int ints[5];
	struct ifmap map;

	/**
	 * ��������������ȡ�����������䵽 ifmap �ṹ��
	 */
	str = get_options(str, ARRAY_SIZE(ints), ints);
	if (!str || !*str)
		return 0;

	/* Save settings */
	memset(&map, 0, sizeof(map));
	if (ints[0] > 0)
		map.irq = ints[1];
	if (ints[0] > 1)
		map.base_addr = ints[2];
	if (ints[0] > 2)
		map.mem_start = ints[3];
	if (ints[0] > 3)
		map.mem_end = ints[4];

	/* Add new entry to the list */
	/**
	 * ͨ�� netdev_boot_setup_add ������ ifmap ��Ϣ���뵽 dev_boot_setup ������
	 */
	return netdev_boot_setup_add(str, &map);
}
/**
 * ���ں˲����а���netdev=ʱ������netdev_boot_setup������
 */
__setup("netdev=", netdev_boot_setup);

/*******************************************************************************

			    Device Interface Subroutines

*******************************************************************************/

/**
 *	__dev_get_by_name	- find a device by its name
 *	@name: name to find
 *
 *	Find an interface by name. Must be called under RTNL semaphore
 *	or @dev_base_lock. If the name is found a pointer to the device
 *	is returned. If the name is not found then %NULL is returned. The
 *	reference counters are not incremented so the caller must be
 *	careful with locks.
 */

struct net_device *__dev_get_by_name(const char *name)
{
	struct hlist_node *p;

	hlist_for_each(p, dev_name_hash(name)) {
		struct net_device *dev
			= hlist_entry(p, struct net_device, name_hlist);
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;
	}
	return NULL;
}

/**
 *	dev_get_by_name		- find a device by its name
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */
/**
 * �����豸���ƣ���hash�������������豸��
 */
struct net_device *dev_get_by_name(const char *name)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(name);
	if (dev)
		dev_hold(dev);
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	__dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold either the RTNL semaphore
 *	or @dev_base_lock.
 */

struct net_device *__dev_get_by_index(int ifindex)
{
	struct hlist_node *p;

	hlist_for_each(p, dev_index_hash(ifindex)) {
		struct net_device *dev
			= hlist_entry(p, struct net_device, index_hlist);
		if (dev->ifindex == ifindex)
			return dev;
	}
	return NULL;
}


/**
 *	dev_get_by_index - find a device by its ifindex
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns NULL if the device
 *	is not found or a pointer to the device. The device returned has
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */
/**
 * �����豸��������hash�������������豸��
 */
struct net_device *dev_get_by_index(int ifindex)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_index(ifindex);
	if (dev)
		dev_hold(dev);
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	dev_getbyhwaddr - find a device by its hardware address
 *	@type: media type of device
 *	@ha: hardware address
 *
 *	Search for an interface by MAC address. Returns NULL if the device
 *	is not found or a pointer to the device. The caller must hold the
 *	rtnl semaphore. The returned device has not had its ref count increased
 *	and the caller must therefore be careful about locking
 *
 *	BUGS:
 *	If the API was consistent this would be __dev_get_by_hwaddr
 */

struct net_device *dev_getbyhwaddr(unsigned short type, char *ha)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for (dev = dev_base; dev; dev = dev->next)
		if (dev->type == type &&
		    !memcmp(dev->dev_addr, ha, dev->addr_len))
			break;
	return dev;
}

struct net_device *dev_getfirstbyhwtype(unsigned short type)
{
	struct net_device *dev;

	rtnl_lock();
	for (dev = dev_base; dev; dev = dev->next) {
		if (dev->type == type) {
			dev_hold(dev);
			break;
		}
	}
	rtnl_unlock();
	return dev;
}

EXPORT_SYMBOL(dev_getfirstbyhwtype);

/**
 *	dev_get_by_flags - find any device with given flags
 *	@if_flags: IFF_* values
 *	@mask: bitmask of bits in if_flags to check
 *
 *	Search for any interface with the given flags. Returns NULL if a device
 *	is not found or a pointer to the device. The device returned has 
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */

struct net_device * dev_get_by_flags(unsigned short if_flags, unsigned short mask)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	for (dev = dev_base; dev != NULL; dev = dev->next) {
		if (((dev->flags ^ if_flags) & mask) == 0) {
			dev_hold(dev);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	return dev;
}

/**
 *	dev_valid_name - check if name is okay for network device
 *	@name: name string
 *
 *	Network device names need to be valid file names to
 *	to allow sysfs to work
 */
static int dev_valid_name(const char *name)
{
	return !(*name == '\0' 
		 || !strcmp(name, ".")
		 || !strcmp(name, "..")
		 || strchr(name, '/'));
}

/**
 *	dev_alloc_name - allocate a name for a device
 *	@dev: device
 *	@name: name format string
 *
 *	Passed a format string - eg "lt%d" it will try and find a suitable
 *	id. Not efficient for many devices, not called a lot. The caller
 *	must hold the dev_base or rtnl lock while allocating the name and
 *	adding the device in order to avoid duplicates. Returns the number
 *	of the unit assigned or a negative errno code.
 */

int dev_alloc_name(struct net_device *dev, const char *name)
{
	int i = 0;
	char buf[IFNAMSIZ];
	const char *p;
	const int max_netdevices = 8*PAGE_SIZE;
	long *inuse;
	struct net_device *d;

	p = strnchr(name, IFNAMSIZ-1, '%');
	if (p) {
		/*
		 * Verify the string as this thing may have come from
		 * the user.  There must be either one "%d" and no other "%"
		 * characters.
		 */
		if (p[1] != 'd' || strchr(p + 2, '%'))
			return -EINVAL;

		/* Use one page as a bit array of possible slots */
		inuse = (long *) get_zeroed_page(GFP_ATOMIC);
		if (!inuse)
			return -ENOMEM;

		for (d = dev_base; d; d = d->next) {
			if (!sscanf(d->name, name, &i))
				continue;
			if (i < 0 || i >= max_netdevices)
				continue;

			/*  avoid cases where sscanf is not exact inverse of printf */
			snprintf(buf, sizeof(buf), name, i);
			if (!strncmp(buf, d->name, IFNAMSIZ))
				set_bit(i, inuse);
		}

		i = find_first_zero_bit(inuse, max_netdevices);
		free_page((unsigned long) inuse);
	}

	snprintf(buf, sizeof(buf), name, i);
	if (!__dev_get_by_name(buf)) {
		strlcpy(dev->name, buf, IFNAMSIZ);
		return i;
	}

	/* It is possible to run out of possible slots
	 * when the name is long and there isn't enough space left
	 * for the digits, or if all bits are used.
	 */
	return -ENFILE;
}


/**
 *	dev_change_name - change name of a device
 *	@dev: device
 *	@newname: name (or format string) must be at least IFNAMSIZ
 *
 *	Change name of a device, can pass format strings "eth%d".
 *	for wildcarding.
 */
int dev_change_name(struct net_device *dev, char *newname)
{
	int err = 0;

	ASSERT_RTNL();

	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (!dev_valid_name(newname))
		return -EINVAL;

	if (strchr(newname, '%')) {
		err = dev_alloc_name(dev, newname);
		if (err < 0)
			return err;
		strcpy(newname, dev->name);
	}
	else if (__dev_get_by_name(newname))
		return -EEXIST;
	else
		strlcpy(dev->name, newname, IFNAMSIZ);

	err = class_device_rename(&dev->class_dev, dev->name);
	if (!err) {
		hlist_del(&dev->name_hlist);
		hlist_add_head(&dev->name_hlist, dev_name_hash(dev->name));
		notifier_call_chain(&netdev_chain, NETDEV_CHANGENAME, dev);
	}

	return err;
}

/**
 *	netdev_state_change - device changes state
 *	@dev: device to cause notification
 *
 *	Called to indicate a device has changed state. This function calls
 *	the notifier chains for netdev_chain and sends a NEWLINK message
 *	to the routing socket.
 */
void netdev_state_change(struct net_device *dev)
{
	if (dev->flags & IFF_UP) {
		notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);
		rtmsg_ifinfo(RTM_NEWLINK, dev, 0);
	}
}

/**
 *	dev_load 	- load a network module
 *	@name: name of interface
 *
 *	If a network interface is not present and the process has suitable
 *	privileges this function loads the module. If module loading is not
 *	available in this kernel then it becomes a nop.
 */

void dev_load(const char *name)
{
	struct net_device *dev;  

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(name);
	read_unlock(&dev_base_lock);

	if (!dev && capable(CAP_SYS_MODULE))
		request_module("%s", name);
}

static int default_rebuild_header(struct sk_buff *skb)
{
	printk(KERN_DEBUG "%s: default_rebuild_header called -- BUG!\n",
	       skb->dev ? skb->dev->name : "NULL!!!");
	kfree_skb(skb);
	return 1;
}


/**
 *	dev_open	- prepare an interface for use.
 *	@dev:	device to open
 *
 *	Takes a device from down to up state. The device's private open
 *	function is invoked and then the multicast lists are loaded. Finally
 *	the device is moved into the up state and a %NETDEV_UP message is
 *	sent to the netdev notifier chain.
 *
 *	Calling this function on an active interface is a nop. On a failure
 *	a negative errno code is returned.
 */
/**
 * ʹ�������豸��
 */
int dev_open(struct net_device *dev)
{
	int ret = 0;

	/*
	 *	Is it already up?
	 */

	if (dev->flags & IFF_UP)
		return 0;

	/*
	 *	Is it even present?
	 */
	if (!netif_device_present(dev))
		return -ENODEV;

	/*
	 *	Call device private open method
	 */
	/**
	 * ����dev->state��__LINK_STATE_START��־λ������豸�򿪲������С�
	 */
	set_bit(__LINK_STATE_START, &dev->state);
	/**
	 * ���dev->open����������������������е��������򶼳�ʼ�����������
	 */
	if (dev->open) {
		ret = dev->open(dev);
		if (ret)
			clear_bit(__LINK_STATE_START, &dev->state);
	}

 	/*
	 *	If it went open OK then:
	 */

	if (!ret) {
		/*
		 *	Set the flags.
		 */
		/**
		 * ����dev->flags��IFF_UP��־λ����豸������
		 */
		dev->flags |= IFF_UP;

		/*
		 *	Initialize multicasting status
		 */
		dev_mc_upload(dev);

		/*
		 *	Wakeup transmit queue engine
		 */
		/**
		 * ����dev_activate��ָ������ʼ�����������õ��Ŷӹ��򣬲��������Ӷ�ʱ����
		 * ����û�û�������������ƣ���ָ��ȱʡ���Ƚ��ȳ�(FIFO)���С�
		 */
		dev_activate(dev);

		/*
		 *	... and announce new interface.
		 */
		/**
		 * ����NETDEV_UP֪ͨ��netdev_chain֪ͨ����֪ͨ���豸ʹ������Ȥ���ں������
		 */
		notifier_call_chain(&netdev_chain, NETDEV_UP, dev);
	}
	return ret;
}

/**
 *	dev_close - shutdown an interface.
 *	@dev: device to shutdown
 *
 *	This function moves an active device into down state. A
 *	%NETDEV_GOING_DOWN is sent to the netdev notifier chain. The device
 *	is then deactivated and finally a %NETDEV_DOWN is sent to the notifier
 *	chain.
 */
/**
 * ��ֹһ�������豸��
 */
int dev_close(struct net_device *dev)
{
	if (!(dev->flags & IFF_UP))
		return 0;

	/*
	 *	Tell people we are going down, so that they can
	 *	prepare to death, when device is still operating.
	 */
	/**
	 * ����NETDEV_GOING_DOWN֪ͨ��netdev_chain֪ͨ����֪ͨ���豸��ֹ����Ȥ���ں������
	 */
	notifier_call_chain(&netdev_chain, NETDEV_GOING_DOWN, dev);

	/**
	 * ����dev_deactivate������ֹ���ڶ��й�������ȷ���豸�������ڴ��䣬��ֹͣ������Ҫ�ļ�ض�ʱ����
	 */
	dev_deactivate(dev);

	/**
	 * ���dev->state��־��__LINK_STATE_START��־λ������豸ж�ء�
	 */
	clear_bit(__LINK_STATE_START, &dev->state);

	/* Synchronize to scheduled poll. We cannot touch poll list,
	 * it can be even on different cpu. So just clear netif_running(),
	 * and wait when poll really will happen. Actually, the best place
	 * for this is inside dev->stop() after device stopped its irq
	 * engine, but this requires more changes in devices. */

	smp_mb__after_clear_bit(); /* Commit netif_running(). */
	/**
	 * �����ѯ�����������ڶ��豸��������ݰ�����ȴ��˶�����ɡ�
	 * ��������__LINK_STATE_START ��־λ����������ٽ���������ѯ���豸�ϵ��ȣ����ڱ�־�����ǰ����һ����ѯ��������
	 */
	while (test_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}

	/*
	 *	Call the device specific close. This cannot fail.
	 *	Only if device is UP
	 *
	 *	We allow it to be called even after a DETACH hot-plug
	 *	event.
	 */
	/**
	 * ���dev->stopָ�벻������������������е��豸��������ʼ���˺���ָ�롣
	 */
	if (dev->stop)
		dev->stop(dev);

	/*
	 *	Device is now down.
	 */
	/**
	 * ���dev->flags��IFF_UP��־λ��ʶ�豸�رա�
	 */
	dev->flags &= ~IFF_UP;

	/*
	 * Tell people we are down
	 */
	/**
	 * ����NETDEV_DOWN֪ͨ��netdev_chain֪ͨ����֪ͨ���豸��ֹ����Ȥ���ں������
	 */
	notifier_call_chain(&netdev_chain, NETDEV_DOWN, dev);

	return 0;
}


/*
 *	Device change register/unregister. These are not inline or static
 *	as we export them to the world.
 */

/**
 *	register_netdevice_notifier - register a network notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when network device events occur.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 *
 * 	When registered all registration and up events are replayed
 *	to the new notifier to allow device to have a race free 
 *	view of the network device list.
 */

int register_netdevice_notifier(struct notifier_block *nb)
{
	struct net_device *dev;
	int err;

	rtnl_lock();
	err = notifier_chain_register(&netdev_chain, nb);
	if (!err) {
		for (dev = dev_base; dev; dev = dev->next) {
			nb->notifier_call(nb, NETDEV_REGISTER, dev);

			if (dev->flags & IFF_UP) 
				nb->notifier_call(nb, NETDEV_UP, dev);
		}
	}
	rtnl_unlock();
	return err;
}

/**
 *	unregister_netdevice_notifier - unregister a network notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_netdevice_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 */

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&netdev_chain, nb);
}

/**
 *	call_netdevice_notifiers - call all network notifier blocks
 *      @val: value passed unmodified to notifier function
 *      @v:   pointer passed unmodified to notifier function
 *
 *	Call all network notifier blocks.  Parameters and return value
 *	are as for notifier_call_chain().
 */

int call_netdevice_notifiers(unsigned long val, void *v)
{
	return notifier_call_chain(&netdev_chain, val, v);
}

/* When > 0 there are consumers of rx skb time stamps */
static atomic_t netstamp_needed = ATOMIC_INIT(0);

void net_enable_timestamp(void)
{
	atomic_inc(&netstamp_needed);
}

void net_disable_timestamp(void)
{
	atomic_dec(&netstamp_needed);
}

static inline void net_timestamp(struct timeval *stamp)
{
	if (atomic_read(&netstamp_needed))
		do_gettimeofday(stamp);
	else {
		stamp->tv_sec = 0;
		stamp->tv_usec = 0;
	}
}

/*
 *	Support routine. Sends outgoing frames to any network
 *	taps currently in use.
 */

void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
	struct packet_type *ptype;
	net_timestamp(&skb->stamp);

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		/* Never send packets back to the socket
		 * they originated from - MvS (miquels@drinkel.ow.org)
		 */
		if ((ptype->dev == dev || !ptype->dev) &&
		    (ptype->af_packet_priv == NULL ||
		     (struct sock *)ptype->af_packet_priv != skb->sk)) {
			struct sk_buff *skb2= skb_clone(skb, GFP_ATOMIC);
			if (!skb2)
				break;

			/* skb->nh should be correctly
			   set by sender, so that the second statement is
			   just protection against buggy protocols.
			 */
			skb2->mac.raw = skb2->data;

			if (skb2->nh.raw < skb2->data ||
			    skb2->nh.raw > skb2->tail) {
				if (net_ratelimit())
					printk(KERN_CRIT "protocol %04x is "
					       "buggy, dev %s\n",
					       skb2->protocol, dev->name);
				skb2->nh.raw = skb2->data;
			}

			skb2->h.raw = skb2->nh.raw;
			skb2->pkt_type = PACKET_OUTGOING;
			ptype->func(skb2, skb->dev, ptype);
		}
	}
	rcu_read_unlock();
}

/*
 * Invalidate hardware checksum when packet is to be mangled, and
 * complete checksum manually on outgoing path.
 */
/**
 * ���������������ͬ����Ϊ�������ڴ��ݲ�������һ���������һ��������
 * �������˵������ʹӲ��У���ʧЧ��
 * �Գ�����˵������������L4У��͡�
 */
int skb_checksum_help(struct sk_buff *skb, int inward)
{
	unsigned int csum;
	int ret = 0, offset = skb->h.raw - skb->data;

	if (inward) {
		skb->ip_summed = CHECKSUM_NONE;
		goto out;
	}

	if (skb_cloned(skb)) {
		ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (ret)
			goto out;
	}

	if (offset > (int)skb->len)
		BUG();
	csum = skb_checksum(skb, offset, skb->len-offset, 0);

	offset = skb->tail - skb->h.raw;
	if (offset <= 0)
		BUG();
	if (skb->csum + 2 > offset)
		BUG();

	*(u16*)(skb->h.raw + skb->csum) = csum_fold(csum);
	skb->ip_summed = CHECKSUM_NONE;
out:	
	return ret;
}

#ifdef CONFIG_HIGHMEM
/* Actually, we should eliminate this check as soon as we know, that:
 * 1. IOMMU is present and allows to map all the memory.
 * 2. No high memory really exists on this machine.
 */

static inline int illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
	int i;

	if (dev->features & NETIF_F_HIGHDMA)
		return 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		if (PageHighMem(skb_shinfo(skb)->frags[i].page))
			return 1;

	return 0;
}
#else
#define illegal_highdma(dev, skb)	(0)
#endif

extern void skb_release_data(struct sk_buff *);

/* Keep head the same: replace data */
/**
 * ����Ƭ��ϳ�һ����һ�Ļ�����
 * ��Ϸ�Ƭ�漰�����ݿ�������������Ӱ��ϵͳ���ܡ�
 */
int __skb_linearize(struct sk_buff *skb, int gfp_mask)
{
	unsigned int size;
	u8 *data;
	long offset;
	struct skb_shared_info *ninfo;
	int headerlen = skb->data - skb->head;
	int expand = (skb->tail + skb->data_len) - skb->end;

	if (skb_shared(skb))
		BUG();

	if (expand <= 0)
		expand = 0;

	size = skb->end - skb->head + expand;
	size = SKB_DATA_ALIGN(size);
	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (!data)
		return -ENOMEM;

	/* Copy entire thing */
	if (skb_copy_bits(skb, -headerlen, data, headerlen + skb->len))
		BUG();

	/* Set up shinfo */
	ninfo = (struct skb_shared_info*)(data + size);
	atomic_set(&ninfo->dataref, 1);
	ninfo->tso_size = skb_shinfo(skb)->tso_size;
	ninfo->tso_segs = skb_shinfo(skb)->tso_segs;
	ninfo->nr_frags = 0;
	ninfo->frag_list = NULL;

	/* Offset between the two in bytes */
	offset = data - skb->head;

	/* Free old data. */
	skb_release_data(skb);

	skb->head = data;
	skb->end  = data + size;

	/* Set up new pointers */
	skb->h.raw   += offset;
	skb->nh.raw  += offset;
	skb->mac.raw += offset;
	skb->tail    += offset;
	skb->data    += offset;

	/* We are no longer a clone, even if we were. */
	skb->cloned    = 0;

	skb->tail     += skb->data_len;
	skb->data_len  = 0;
	return 0;
}

#define HARD_TX_LOCK(dev, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		spin_lock(&dev->xmit_lock);		\
		dev->xmit_lock_owner = cpu;		\
	}						\
}

#define HARD_TX_UNLOCK(dev) {				\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		dev->xmit_lock_owner = -1;		\
		spin_unlock(&dev->xmit_lock);		\
	}						\
}

/**
 *	dev_queue_xmit - transmit a buffer
 *	@skb: buffer to transmit
 *
 *	Queue a buffer for transmission to a network device. The caller must
 *	have set the device and priority and built the buffer before calling
 *	this function. The function can be called from an interrupt.
 *
 *	A negative errno code is returned on a failure. A success does not
 *	guarantee the frame will be transmitted as it may be dropped due
 *	to congestion or traffic shaping.
 */
/**
 * ���ͱ��ĵ���������dev_queue_xmit�ܹ�ͨ������·���������������ͺ���hard_start_xmit��ִ�У�
 *		���������ƵĽӿڣ�QoS�㣩������ͨ��qdisc_run������ɵġ�
 *		ֱ�ӵ���hard_start_xmit�����豸��ʹ���������ƻ���ʱ��
 */
int dev_queue_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct Qdisc *q;
	int rc = -ENOMEM;

	/**
	 * ��skb_shinfo(skb)->frag_list�ǿ�ʱ����Ч������һ����Ƭ�б�
	 * ��������£���Ч�����ǵ�һ�Ŀ顣
	 */
	if (skb_shinfo(skb)->frag_list &&
		/**
		 * �����Ƭ�ˣ��������豸�Ƿ�֧�ַ�ɢ/�ۼ�DMA���ܡ������֧�֣������н���Ƭ�ϲ�����һ��������
		 */
	    !(dev->features & NETIF_F_FRAGLIST) &&
	    /**
	     * �ϲ���Ƭ
	     */
	    __skb_linearize(skb, GFP_ATOMIC))
		goto out_kfree_skb;

	/* Fragmented skb is linearized if device does not support SG,
	 * or if at least one of fragments is in highmem and device
	 * does not support DMA from it.
	 */
	/**
	 * ������ı���Ƭ�������豸��֧�ַ�Ƭ���ͻ���ĳ����Ƭ�ڸ߶��ڴ棬Ҳ��Ҫ�ϲ���Ƭ��
	 */
	if (skb_shinfo(skb)->nr_frags &&
	    (!(dev->features & NETIF_F_SG) || illegal_highdma(dev, skb)) &&
	    __skb_linearize(skb, GFP_ATOMIC))
		goto out_kfree_skb;

	/* If packet is not checksummed and device does not support
	 * checksumming for this protocol, complete checksumming here.
	 */
	/**
	 * �����û�м���У��͡�һ������£����������֮ǰ����У��ͣ�����ĳЩ����£���������м���У��͡�
	 */
	if (skb->ip_summed == CHECKSUM_HW &&
		/**
		 * Ӳ����֧��У��ͼ��㣬������������㡣
		 */
	    (!(dev->features & (NETIF_F_HW_CSUM | NETIF_F_NO_CSUM)) &&
	    /**
		 * Ӳ��ֻ֧��IP���У��ͼ��㣬���Ǳ��Ĳ���IPЭ�顣
		 */
	     (!(dev->features & NETIF_F_IP_CSUM) ||
	      skb->protocol != htons(ETH_P_IP))))
	      	/**
	      	 * ����������У���ʧ�ܣ����˳���
	      	 */
	      	if (skb_checksum_help(skb, 0))
	      		goto out_kfree_skb;

	/* Disable soft irqs for various locks below. Also 
	 * stops preemption for RCU. 
	 */
	local_bh_disable(); 

	/* Updates of qdisc are serialized by queue_lock. 
	 * The struct Qdisc which is pointed to by qdisc is now a 
	 * rcu structure - it may be accessed without acquiring 
	 * a lock (but the structure may be stale.) The freeing of the
	 * qdisc will be deferred until it's known that there are no 
	 * more references to it.
	 * 
	 * If the qdisc has an enqueue function, we still need to 
	 * hold the queue_lock before calling it, since queue_lock
	 * also serializes access to the device queue.
	 */

	/**
	 * һ��У��ͱ������ˣ����а�ͷ��׼���ã���һ�����Ǿ���������һ��֡��
	 * ��ʱ��������Ϊ���ÿ��豸�Ƿ�֧���������ƣ����֧���������ƣ����ڶ��гͷ������⡣
	 * ��Ҳ�����˸е���֣�����ֻ�Ǵ���һ���������������Ҫ�ͽ��з�Ƭ��ϼ�У��ͣ�������ȴ�����ڶ��гͷ���
	 * �ӳ����е�״̬����ǰ������ܲ�����һ����Ҫ���͵İ���
	 */
	q = rcu_dereference(dev->qdisc);
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd,AT_EGRESS);
#endif

	/**
     * ������ڶ��гͷ�����ô�豸�ܵ�dev->qdisc��Ӱ�졣����֡��enqueue�麯�������Ŷӣ�������qdisc_run���г��Ӻʹ���
 	 */
	if (q->enqueue) {
		/* Grab device queue */
		/**
		 * ���Ӻ���Ӷ��ɶ����ϵ�queue_lock�����������ж�Ҳ��local_bh_disable��ֹ��Ҳͨ��RCU��ֹ����ռ��
		 */
		spin_lock(&dev->queue_lock);

		/**
		 * ������ӡ����ڶ��д�����ԭ��disc_run��ȡ���Ĵ����Ͱ�����һ���Ǹ���ӵİ���
		 */
		rc = q->enqueue(skb, q);

		qdisc_run(dev);

		spin_unlock(&dev->queue_lock);
		rc = rc == NET_XMIT_BYPASS ? NET_XMIT_SUCCESS : rc;
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that xmit_lock protection is necessary here.
	   (f.e. loopback and IP tunnels are clean ignoring statistics
	   counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	/**
	 * �豸û�ж��У������ǻ����豸�������豸��
	 * ֱ�ӷ������ǡ�
	 */
	if (dev->flags & IFF_UP) {/* һ�㶼���������־ */
		int cpu = smp_processor_id(); /* ok because BHs are off */

		if (dev->xmit_lock_owner != cpu) {/* Ӧ�ò��������� */
			/**
			 * HARD_TX_LOCKʹ��spin_lock������spin_trylock�����������������CPU����ˣ�dev_queue_xmit������ֱ�������ͷš�
			 */
			HARD_TX_LOCK(dev, cpu);

			if (!netif_queue_stopped(dev)) {/* �ᱻֹͣ��? */
				/**
				 * ���Ͱ���AF_PACKETЭ�顣
				 */
				if (netdev_nit)
					dev_queue_xmit_nit(skb, dev);

				rc = 0;
				/**
				 * �������豸���͡�
				 */
				if (!dev->hard_start_xmit(skb, dev)) {
					HARD_TX_UNLOCK(dev);
					goto out;
				}
			}
			/**
			 * ���Ժ��״̬���ǲ�̫�����ġ�
			 */
			HARD_TX_UNLOCK(dev);
			if (net_ratelimit())
				printk(KERN_CRIT "Virtual device %s asks to "
				       "queue packet!\n", dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately */
			if (net_ratelimit())
				printk(KERN_CRIT "Dead loop on virtual device "
				       "%s, fix it urgently!\n", dev->name);
		}
	}

	rc = -ENETDOWN;
	local_bh_enable();

out_kfree_skb:
	kfree_skb(skb);
	return rc;
out:
	local_bh_enable();
	return rc;
}


/*=======================================================================
			Receiver routines
  =======================================================================*/

/**
 * ʹ�÷�NAPIʱ��ÿ��CPU��������е���󳤶ȡ�����ͨ��proc�޸ġ�
 * �������Ӧ���ڷ�NAPI�豸����ΪNAPIʹ��˽�ж��У��豸����ѡ����Ե����ֵ��ͨ����16,32,64��10G��̫������driver/net/s2io.cʹ�ø����ֵ��90��
 */
int netdev_max_backlog = 300;
int weight_p = 64;            /* old backlog weight */
/* These numbers are selected based on intuition and some
 * experimentatiom, if you have more scientific way of doing this
 * please go ahead and fix things.
 */
int no_cong_thresh = 10;
int no_cong = 20;
int lo_cong = 100;
int mod_cong = 290;

DEFINE_PER_CPU(struct netif_rx_stats, netdev_rx_stat) = { 0, };

/**
 * ����ƽ�����г��Ⱥ�ӵ������
 * ÿ�ν��յ�һ���µ�֡ʱ���������������ԵĶ�ʱ���н��м��㡣
 * Ҫÿ�ν��յ�һ���µ�֡ʱ���м��㣬��Ҫ����OFFLINE_SAMPLE�������Ϊʲô��netif_rx�У�ִ��get_sample_stats������OFFLINE_SAMPLE��Ĭ�����Ǳ���ֹ��
 */
static void get_sample_stats(int cpu)
{
#ifdef RAND_LIE
	unsigned long rd;
	int rq;
#endif
	struct softnet_data *sd = &per_cpu(softnet_data, cpu);
	int blog = sd->input_pkt_queue.qlen;
	int avg_blog = sd->avg_blog;

	/**
	 * ���ڱ��������������ã���ˣ�������������򵥵Ĺ�ʽ����ƽ�����ȡ�
	 */
	avg_blog = (avg_blog >> 1) + (blog >> 1);

	if (avg_blog > mod_cong) {
		/* Above moderate congestion levels. */
		sd->cng_level = NET_RX_CN_HIGH;
		/**
		 * RAND_LIE���Խ�ӵ����������ĵ��ߡ�������������Ķ���һЩ�����
		 * �ڶ���������������е�����£����Է�ֹ�������������������󣬵���������Ĳ���ƽ�ԡ�
		 */
#ifdef RAND_LIE
		rd = net_random();
		rq = rd % netdev_max_backlog;
		if (rq < avg_blog) /* unlucky bastard */
			sd->cng_level = NET_RX_DROP;
#endif
	} else if (avg_blog > lo_cong) {
		sd->cng_level = NET_RX_CN_MOD;
#ifdef RAND_LIE
		rd = net_random();
		rq = rd % netdev_max_backlog;
			if (rq < avg_blog) /* unlucky bastard */
				sd->cng_level = NET_RX_CN_HIGH;
#endif
	} else if (avg_blog > no_cong)
		sd->cng_level = NET_RX_CN_LOW;
	else  /* no congestion */
		sd->cng_level = NET_RX_SUCCESS;

	sd->avg_blog = avg_blog;
}

#ifdef OFFLINE_SAMPLE
static void sample_queue(unsigned long dummy)
{
/* 10 ms 0r 1ms -- i don't care -- JHS */
	int next_tick = 1;
	int cpu = smp_processor_id();

	get_sample_stats(cpu);
	next_tick += jiffies;
	mod_timer(&samp_timer, next_tick);
}
#endif


/**
 *	netif_rx	-	post buffer to the network code
 *	@skb: buffer to post
 *
 *	This function receives a packet from a device driver and queues it for
 *	the upper (protocol) levels to process.  It always succeeds. The buffer
 *	may be dropped during processing for congestion control or by the
 *	protocol layers.
 *
 *	return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_CN_LOW   (low congestion)
 *	NET_RX_CN_MOD   (moderate congestion)
 *	NET_RX_CN_HIGH  (high congestion)
 *	NET_RX_DROP     (packet was dropped)
 *
 */
/**
 * ���ж��д�����֡�ķ��������ڷ�NAPI������һ���������ж������ġ�
 * 		skb:	���յ��Ļ�������
 * ����ֵ:		ӵ������
 */
int netif_rx(struct sk_buff *skb)
{
	int this_cpu;
	struct softnet_data *queue;
	unsigned long flags;

#ifdef CONFIG_NETPOLL
	/**
	 * ���netpoll�ػ�˰������˳���
	 */
	if (skb->dev->netpoll_rx && netpoll_rx(skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
#endif
	/**
	 * ��û�����ð��Ľ���ʱ�䣬����������
	 */
	if (!skb->stamp.tv_sec)
		/**
		 * net_enable_timestamp��ʾ�����˶�ʱ�������Ȥ��ֻ���������Ÿ���stamp��
		 * ������net_timestamp���жϵġ�
		 * ���������õ�ʱ�䣬������豸�ģ����ұ������tick.
		 */
		net_timestamp(&skb->stamp);

	/*
	 * The code is rearranged so that the path is the most
	 * short when CPU is congested, but is still operating.
	 */
	/**
	 * netif_rxͨ�����������ж��������е��á�
	 * ����Ҳ�����⣬�ر��ǵ��ػ��豸�����������ʱ��
	 * �������ԭ��netif_rx������ʱ��ֹ����CPU�жϣ���������ʱ�������´��жϡ�
	 */
	local_irq_save(flags);
	/**
	 * ��ȡÿCPU softnet_data���ݽṹ�������ü�����
	 */
	this_cpu = smp_processor_id();
	queue = &__get_cpu_var(softnet_data);

	__get_cpu_var(netdev_rx_stat).total++;
	/**
	 * �ж�CPU����������Ƿ����ˡ�
	 */
	if (queue->input_pkt_queue.qlen <= netdev_max_backlog) {
		/**
		 * �����������Ѿ���Ϊӵ��״̬�ˣ��Ͷ�������
		 */
		if (queue->input_pkt_queue.qlen) {
			if (queue->throttle)
				goto drop;

enqueue:
			/**
			 * ���л�û��ӵ������������������е�β����
			 * dev_hold(skb->dev)���������豸�����ü���������豸���ܱ�ɾ����ֱ�����屻�����ݼ�������dev_put��ɣ��ⷢ����net_rx_action
			 */
			dev_hold(skb->dev);
			__skb_queue_tail(&queue->input_pkt_queue, skb);
#ifndef OFFLINE_SAMPLE
			/**
			 * Avg_blog��cng_level��get_sample_status�и���
			 */
			get_sample_stats(this_cpu);
#endif
			local_irq_restore(flags);
			/**
			 * ���ص�ǰӵ����������������Ը��ݴ�ֵȷ���Ƿ��������ж�����
			 */
			return queue->cng_level;
		}

		/**
		 * ��ǰ�ж�Ϊ�գ����ҵ�ǰ״̬Ϊӵ��״̬����Ӧ����ӵ��״̬����ΪFALSE��
		 * ʵ����������ϲ����ܷ�������Ϊthrottle״̬Ӧ����֮ǰ���Ѿ������ˡ�
		 * ��һ��֡����һ���ն���ʱ���������Ҳ������process_backlog�з�����
		 */
		if (queue->throttle)
			queue->throttle = 0;

		/**
		 * ����ᴥ�����жϴ����ġ�
		 * ע�⣺�����»�������ӵ�һ���յĶ�����ʱ��netif_rx_schedule�Żᱻ���á�������Ϊ������зǿգ�NET_RX_SOFTIRQ�Ѿ������ȣ�û�б�Ҫ�ٵ������ˡ�
		 */
		netif_rx_schedule(&queue->backlog_dev);
		goto enqueue;
	}

	/**
	 * CPU��������Ѿ����ˣ����ҵ�ǰ״̬����ӵ��״̬�������ø�״̬��
	 * ����ӵ������ͳ�Ƽ�һ��Ȼ��������
	 */
	if (!queue->throttle) {
		queue->throttle = 1;
		__get_cpu_var(netdev_rx_stat).throttled++;
	}

drop:
	/**
	 * ���ö��������˳���
	 */
	__get_cpu_var(netdev_rx_stat).dropped++;
	local_irq_restore(flags);

	/**
	 * �ͷ�skb
	 */
	kfree_skb(skb);
	return NET_RX_DROP;
}

/**
 * netif_rx����ú������������ڷ��ж������ġ����������£�����TUN����ʹ�á�
 */
int netif_rx_ni(struct sk_buff *skb)
{
	int err;

	preempt_disable();
	err = netif_rx(skb);
	if (local_softirq_pending())
		do_softirq();
	preempt_enable();

	return err;
}

EXPORT_SYMBOL(netif_rx_ni);

static __inline__ void skb_bond(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;

	if (dev->master) {
		skb->real_dev = skb->dev;
		skb->dev = dev->master;
	}
}

/**
 * ������������жϡ������豸�����������ض����������Լ�������.
 */
static void net_tx_action(struct softirq_action *h)
{
	struct softnet_data *sd = &__get_cpu_var(softnet_data);

	/**
	 * �ͷŻ���������Щ������������ͨ������dev_kfree_skb_irq��ӵ�completion_queue����
	 */
	if (sd->completion_queue) {
		struct sk_buff *clist;

		/**
		 * ����net_tx_action�����ڷ��ж������ģ��豸�����������κ�ʱ�佫���ӵ������У�����ڷ���softnet_data�ṹʱ��net_tx_action�����ֹ�жϡ�
		 */
		local_irq_disable();
		/**
		 * ��ֹ�жϵ�ʱ��Ӧ�������ܵĶ̣���ͨ������completion_queueΪ��������������ұ�������ָ�뵽һ���ֲ�����clist�С�
		 * ������û��˭�ܹ���������ע�⣺ÿ��CPU�������Լ���������
		 * �����ܹ�����������ͨ��__kfree_skb�ͷ�ÿ��Ԫ�أ�����ʱ���������Լ�����completion_queue������½�㡣
		 */
		clist = sd->completion_queue;
		sd->completion_queue = NULL;
		local_irq_enable();

		/**
		 * ������ʱ�����е�����Ԫ�أ�����sk_buff�ͷŵ���
		 */
		while (clist) {
			struct sk_buff *skb = clist;
			clist = clist->next;

			BUG_TRAP(!atomic_read(&skb->users));
			__kfree_skb(skb);
		}
	}

	/**
	 * ����֡�������һ�������ƣ�Ҳʹ��һ���ֲ�������
	 */
	if (sd->output_queue) {
		struct net_device *head;

		local_irq_disable();
		head = sd->output_queue;
		sd->output_queue = NULL;
		local_irq_enable();

		/**
		 * ���������е������豸��
		 */
		while (head) {
			struct net_device *dev = head;
			head = head->next_sched;

			smp_mb__before_clear_bit();
			clear_bit(__LINK_STATE_SCHED, &dev->state);

			/**
			 * ע�⣺��ÿ���豸��˵���ڿ�ʼ����ǰ����������Ҫ����豸��������dev->queue_lock����
			 * ����������ܻ��������������CPU����ˣ������򵥵�ʹ��netif_schedule���µ����豸��������
			 */
			if (spin_trylock(&dev->queue_lock)) {
				qdisc_run(dev);
				spin_unlock(&dev->queue_lock);
			} else {
				netif_schedule(dev);
			}
		}
	}
}

static __inline__ int deliver_skb(struct sk_buff *skb,
				  struct packet_type *pt_prev)
{
	atomic_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev);
}

#if defined(CONFIG_BRIDGE) || defined (CONFIG_BRIDGE_MODULE)
int (*br_handle_frame_hook)(struct net_bridge_port *p, struct sk_buff **pskb);

/**
 * �����յ���ʱ�������Ž����顣
 */
static __inline__ int handle_bridge(struct sk_buff **pskb,
				    struct packet_type **pt_prev, int *ret)
{
	struct net_bridge_port *port;

	/**
	 * �������صİ������߽����豸���������豸�����˳���
	 */
	if ((*pskb)->pkt_type == PACKET_LOOPBACK ||
	    (port = rcu_dereference((*pskb)->dev->br_port)) == NULL)
		return 0;

	if (*pt_prev) {
		*ret = deliver_skb(*pskb, *pt_prev);
		*pt_prev = NULL;
	} 

	/**
	 * br_handle_frame_hook�������ڴ���������صİ���������ʼ��Ϊbr_handle_frame��
	 */
	return br_handle_frame_hook(port, pskb);
}
#else
#define handle_bridge(skb, pt_prev, ret)	(0)
#endif

#ifdef CONFIG_NET_CLS_ACT
/* TODO: Maybe we should just force sch_ingress to be compiled in
 * when CONFIG_NET_CLS_ACT is? otherwise some useless instructions
 * a compare and 2 stores extra right now if we dont have it on
 * but have CONFIG_NET_CLS_ACT
 * NOTE: This doesnt stop any functionality; if you dont have 
 * the ingress scheduler, you just cant add policies on ingress.
 *
 */
static int ing_filter(struct sk_buff *skb) 
{
	struct Qdisc *q;
	struct net_device *dev = skb->dev;
	int result = TC_ACT_OK;
	
	if (dev->qdisc_ingress) {
		__u32 ttl = (__u32) G_TC_RTTL(skb->tc_verd);
		if (MAX_RED_LOOP < ttl++) {
			printk("Redir loop detected Dropping packet (%s->%s)\n",
				skb->input_dev?skb->input_dev->name:"??",skb->dev->name);
			return TC_ACT_SHOT;
		}

		skb->tc_verd = SET_TC_RTTL(skb->tc_verd,ttl);

		skb->tc_verd = SET_TC_AT(skb->tc_verd,AT_INGRESS);
		if (NULL == skb->input_dev) {
			skb->input_dev = skb->dev;
			printk("ing_filter:  fixed  %s out %s\n",skb->input_dev->name,skb->dev->name);
		}
		spin_lock(&dev->ingress_lock);
		if ((q = dev->qdisc_ingress) != NULL)
			result = q->enqueue(skb, q);
		spin_unlock(&dev->ingress_lock);

	}

	return result;
}
#endif

/**
 * ���ж��д����ĵ���������������NAPI�ͷ�NAPI��
 */
int netif_receive_skb(struct sk_buff *skb)
{
	struct packet_type *ptype, *pt_prev;
	int ret = NET_RX_DROP;
	unsigned short type;

#ifdef CONFIG_NETPOLL
	if (skb->dev->netpoll_rx && skb->dev->poll && netpoll_rx(skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
#endif

	/**
	 * ����Ĵ����ƺ��Ƕ���ģ�Ҳ����Ϊ�������������ݣ�����ȥ��Ӧ��û�����⡣
	 */
	if (!skb->stamp.tv_sec)
		net_timestamp(&skb->stamp);

	/**
	 * �󶨹�������һ�������ܹ��������һ�𣬲�������һ����һ���������д���
	 * �������֡�����������������飬sk_buff���ݽṹ�еĽӿڱ��������netif_receive_skb�ַ�����L3�㴦��ӿ�ǰ������豸��
	 */
	skb_bond(skb);

	/**
	 * ��֡������
	 */
	__get_cpu_var(netdev_rx_stat).total++;

	/**
	 * ��ʼ��L2��L3��L4��Э����ʼ��ַ��
	 */
	skb->h.raw = skb->nh.raw = skb->data;
	/**
	 * mac���ȣ�L3��ַ��ȥL2��ַ���ɡ�
	 */
	skb->mac_len = skb->nh.raw - skb->mac.raw;

	pt_prev = NULL;

	rcu_read_lock();

#ifdef CONFIG_NET_CLS_ACT
	/**
	 * ���ﴦ���������ơ�
	 */
	if (skb->tc_verd & TC_NCLS) {
		skb->tc_verd = CLR_TC_NCLS(skb->tc_verd);
		goto ncls;
	}
#endif

	/**
	 * ptype_all�е�Э�鴦������Э�����ͣ�һ������̽������Э�顣
	 * ���ｫ���������Ǵ���
	 */
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		if (!ptype->dev || ptype->dev == skb->dev) {
			if (pt_prev) 
				ret = deliver_skb(skb, pt_prev);
			pt_prev = ptype;
		}
	}

#ifdef CONFIG_NET_CLS_ACT
	if (pt_prev) {
		ret = deliver_skb(skb, pt_prev);
		pt_prev = NULL; /* noone else should process this after*/
	} else {
		skb->tc_verd = SET_TC_OK2MUNGE(skb->tc_verd);
	}

	/**
	 * ing_filter���ڴ����������ơ�
	 */
	ret = ing_filter(skb);

	if (ret == TC_ACT_SHOT || (ret == TC_ACT_STOLEN)) {
		kfree_skb(skb);
		goto out;
	}

	skb->tc_verd = 0;
ncls:
#endif

	/**
	 * ���������ں˸ı�֡��L2��ԭʼĿ���ַ����Щ֡��Ŀ���ַָ������������������֡�ܹ���ת���������ں˿��Ա��������ı�׼�÷����Ծ����Ƿ�ת��֡�����ı�׼�÷��У�
 	 * 		����IP��������L4��Э�飩
 	 *		����TCP��
 	 *		�ض��˿��ϵ�TCP����
 	 *		����UDP��
 	 *		�ض��˿��ϵ�UDP����
	 * ����handle_diverter�Ծ����Ƿ�ı�MACĿ�ĵ�ַ�����⣬����ı�Ŀ��MAC��ַ�Ļ���skb->pkt_typeҲ����ı�ΪPACKET_HOST��
	 */
	handle_diverter(skb);

	/**
	 * �������š�
	 * ÿһ��net_device���ݽṹ��һ��ָ��net_bridge_port�����ݽṹ��
	 * �ⱻ�����洢��ʾ�ŽӶ˿ڵ���չ��Ϣ�����ӿڲ������Ž�ʱ������ֵΪ�ա�
	 * ��һ���˿ڱ����ó��ŽӶ˿�ʱ���ں˽�����עL2ͷ��
	 */
	if (handle_bridge(&skb, &pt_prev, &ret))
		goto out;

	/**
	 * �����ַ���L3��Э�鴦��
	 */
	type = skb->protocol;
	list_for_each_entry_rcu(ptype, &ptype_base[ntohs(type)&15], list) {
		if (ptype->type == type &&
		    (!ptype->dev || ptype->dev == skb->dev)) {
			if (pt_prev) 
				ret = deliver_skb(skb, pt_prev);
			pt_prev = ptype;
		}
	}

	if (pt_prev) {
		ret = pt_prev->func(skb, skb->dev, pt_prev);
	} else {
		kfree_skb(skb);
		/* Jamal, now you will not able to escape explaining
		 * me how you were going to use this. :-)
		 */
		ret = NET_RX_DROP;
	}

out:
	rcu_read_unlock();
	return ret;
}

/**
 * ��NAPI�ܹ��£�һЩ���豸������֧��NAPI����Ȼ������ŵ�ÿCPU���豸������������С�
 * process_backlog������ΪĬ�ϵ�poll��������������������еİ���
 * ���������д˺���ʱ���жϱ��򿪣����������жϿ��ܴ�ϱ�����������������Ҫ����softnet_data������ڷ��ʴ˽ṹʱ����Ҫ���жϱ�����
 */
static int process_backlog(struct net_device *backlog_dev, int *budget)
{
	int work = 0;
	int quota = min(backlog_dev->quota, *budget);
	struct softnet_data *queue = &__get_cpu_var(softnet_data);
	unsigned long start_time = jiffies;

	/**
	 * ��ʼ��ѭ������ͼ���������ȡ��������������������֮һ�õ�����ʱ��ֹѭ����
 	*		�����Ѿ�Ϊ�ա�
 	*		�豸����Ѿ����ꡣ
 	*		�����������㹻����ʱ�䡣
	 */
	for (;;) {
		struct sk_buff *skb;
		struct net_device *dev;

		/**
		 * ����Ҫ��������������У����Ҷ���豸���ܲ����ж��������д������ˣ��ڲ���ʱ����Ҫ�ر��жϡ�
		 * ���Ǳ�������NAPI�豸��poll������֮ͬ����
		 */
		local_irq_disable();
		/**
		 * ȡ��������İ���
		 */
		skb = __skb_dequeue(&queue->input_pkt_queue);
		if (!skb)
			goto job_done;
		local_irq_enable();

		dev = skb->dev;

		/**
		 * ����֡����������������NAPI���Ƿ�NAPI��������ô˺����������ݸ��ϲ�Э��ջ����
		 */
		netif_receive_skb(skb);

		dev_put(dev);

		work++;

		if (work >= quota || jiffies - start_time > 1)
			break;

	}

	/**
	 * ���ݱ��δ���İ��������޸��豸��
	 */
	backlog_dev->quota -= work;
	*budget -= work;
	return -1;

/**
 * ���������Ѿ�����ˣ���ѭ����ת��job_done��
 */
job_done:
	backlog_dev->quota -= work;
	*budget -= work;

	/**
	 * �豸����poll_list���Ƴ���һ���豸�������û���κλ�����Ҫ����__LINK_STATE_RX_SCHED��־Ҳ���������������ٱ�backlog������̵��ȡ�
	 */
	list_del(&backlog_dev->poll_list);
	smp_mb__before_clear_bit();
	netif_poll_enable(backlog_dev);

	/**
	 * ����������е�����㣬throttle״̬���������������������ˣ�
	 */
	if (queue->throttle)
		queue->throttle = 0;
	local_irq_enable();
	return 0;
}

/**
 * ����֡�����жϴ�������
 * �������ط���֡�ȴ�net_rx_action����
 *		������ض�CPU�Ķ��У���NAPI�豸���жϴ�������netif_rx����֡�ŵ�softnet_data->input_pkt_queue��
 *		�豸�ڴ棺��NAPIʹ�õ��豸poll����ֱ�Ӵ��豸�����������Ľ��ջ�����������ȡ֡��
 */
static void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *queue = &__get_cpu_var(softnet_data);
	unsigned long start_time = jiffies;
	int budget = netdev_max_backlog;

	
	local_irq_disable();

	/**
	 * �����ȴ���ѯ���豸����
	 */
	while (!list_empty(&queue->poll_list)) {
		struct net_device *dev;

		/**
		 * �����ǰ�豸��û����������ȫ�����������豸һ�����ᣬͨ��poll�����Ӷ�����ȡ��������
		 */
		if (budget <= 0 || jiffies - start_time > 1)
			goto softnet_break;

		local_irq_enable();

		/**
 		 * ���ڴ��жϺ��豸����ֻ����poll_list�������豸��������ɾ����
 		 * ��ˣ�����ȡ��һ���豸��û������ġ�
		 */
		dev = list_entry(queue->poll_list.next,
				 struct net_device, poll_list);

		/**
		 * ���dev_poll��Ϊ�豸���ò�����ȡ������������е����л�������أ���������£������ط�0ֵ�����豸���Ƶ�poll_list��ĩβ
		 * ����net_dev_init�б�Ĭ�ϵĳ�ʼ��Ϊprocess_backlog����Ϊ��Щ�豸��ʹ��NAPI��
		 */
		if (dev->quota <= 0 || dev->poll(dev, &budget)) {
			local_irq_disable();
			/**
			 * ���豸�Ƶ�����β����
			 */
			list_del(&dev->poll_list);
			list_add_tail(&dev->poll_list, &queue->poll_list);
			/**
			 * �����豸��
			 */
			if (dev->quota < 0)
				dev->quota += dev->weight;
			else
				dev->quota = dev->weight;
		} else {
			/**
			 * ��poll����net_rx_action����ն��У�net_rx_action����poll_list���Ƴ��豸���ٶ�poll�Ѿ���netif_rx_complete��������
			 * �����ж��У����ٶ��豸�����ü�����
			 */
			dev_put(dev);
			/**
			 * ��Ҫ����������ж��ˣ��˴���Ҫ���жϡ�
			 */
			local_irq_disable();
		}
	}
out:
	local_irq_enable();
	return;

softnet_break:
	/**
	 * �˼�����ʾ����һ���������߳�ʱ�հ��Ĵ�����
	 */
	__get_cpu_var(netdev_rx_stat).time_squeeze++;
	/**
	 * ���ڻ����豸��Ҫ�հ�����˴�����һ�����ж��հ���
	 */
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	goto out;
}

static gifconf_func_t * gifconf_list [NPROTO];

/**
 *	register_gifconf	-	register a SIOCGIF handler
 *	@family: Address family
 *	@gifconf: Function handler
 *
 *	Register protocol dependent address dumping routines. The handler
 *	that is passed must not be freed or reused until it has been replaced
 *	by another handler.
 */
int register_gifconf(unsigned int family, gifconf_func_t * gifconf)
{
	if (family >= NPROTO)
		return -EINVAL;
	gifconf_list[family] = gifconf;
	return 0;
}


/*
 *	Map an interface index to its name (SIOCGIFNAME)
 */

/*
 *	We need this ioctl for efficient implementation of the
 *	if_indextoname() function required by the IPv6 API.  Without
 *	it, we would have to search all the interfaces to find a
 *	match.  --pb
 */

static int dev_ifname(struct ifreq __user *arg)
{
	struct net_device *dev;
	struct ifreq ifr;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_index(ifr.ifr_ifindex);
	if (!dev) {
		read_unlock(&dev_base_lock);
		return -ENODEV;
	}

	strcpy(ifr.ifr_name, dev->name);
	read_unlock(&dev_base_lock);

	if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

/*
 *	Perform a SIOCGIFCONF call. This structure will change
 *	size eventually, and there is nothing I can do about it.
 *	Thus we will need a 'compatibility mode'.
 */

static int dev_ifconf(char __user *arg)
{
	struct ifconf ifc;
	struct net_device *dev;
	char __user *pos;
	int len;
	int total;
	int i;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifc, arg, sizeof(struct ifconf)))
		return -EFAULT;

	pos = ifc.ifc_buf;
	len = ifc.ifc_len;

	/*
	 *	Loop over the interfaces, and write an info block for each.
	 */

	total = 0;
	for (dev = dev_base; dev; dev = dev->next) {
		for (i = 0; i < NPROTO; i++) {
			if (gifconf_list[i]) {
				int done;
				if (!pos)
					done = gifconf_list[i](dev, NULL, 0);
				else
					done = gifconf_list[i](dev, pos + total,
							       len - total);
				if (done < 0)
					return -EFAULT;
				total += done;
			}
		}
  	}

	/*
	 *	All done.  Write the updated control block back to the caller.
	 */
	ifc.ifc_len = total;

	/*
	 * 	Both BSD and Solaris return 0 here, so we do too.
	 */
	return copy_to_user(arg, &ifc, sizeof(struct ifconf)) ? -EFAULT : 0;
}

#ifdef CONFIG_PROC_FS
/*
 *	This is invoked by the /proc filesystem handler to display a device
 *	in detail.
 */
static __inline__ struct net_device *dev_get_idx(loff_t pos)
{
	struct net_device *dev;
	loff_t i;

	for (i = 0, dev = dev_base; dev && i < pos; ++i, dev = dev->next);

	return i == pos ? dev : NULL;
}

void *dev_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&dev_base_lock);
	return *pos ? dev_get_idx(*pos - 1) : SEQ_START_TOKEN;
}

void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return v == SEQ_START_TOKEN ? dev_base : ((struct net_device *)v)->next;
}

void dev_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&dev_base_lock);
}

static void dev_seq_printf_stats(struct seq_file *seq, struct net_device *dev)
{
	if (dev->get_stats) {
		struct net_device_stats *stats = dev->get_stats(dev);

		seq_printf(seq, "%6s:%8lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu "
				"%8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu\n",
			   dev->name, stats->rx_bytes, stats->rx_packets,
			   stats->rx_errors,
			   stats->rx_dropped + stats->rx_missed_errors,
			   stats->rx_fifo_errors,
			   stats->rx_length_errors + stats->rx_over_errors +
			     stats->rx_crc_errors + stats->rx_frame_errors,
			   stats->rx_compressed, stats->multicast,
			   stats->tx_bytes, stats->tx_packets,
			   stats->tx_errors, stats->tx_dropped,
			   stats->tx_fifo_errors, stats->collisions,
			   stats->tx_carrier_errors +
			     stats->tx_aborted_errors +
			     stats->tx_window_errors +
			     stats->tx_heartbeat_errors,
			   stats->tx_compressed);
	} else
		seq_printf(seq, "%6s: No statistics available.\n", dev->name);
}

/*
 *	Called from the PROCfs module. This now uses the new arbitrary sized
 *	/proc/net interface to create /proc/net/dev
 */
static int dev_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Inter-|   Receive                            "
			      "                    |  Transmit\n"
			      " face |bytes    packets errs drop fifo frame "
			      "compressed multicast|bytes    packets errs "
			      "drop fifo colls carrier compressed\n");
	else
		dev_seq_printf_stats(seq, v);
	return 0;
}

static struct netif_rx_stats *softnet_get_online(loff_t *pos)
{
	struct netif_rx_stats *rc = NULL;

	while (*pos < NR_CPUS)
	       	if (cpu_online(*pos)) {
			rc = &per_cpu(netdev_rx_stat, *pos);
			break;
		} else
			++*pos;
	return rc;
}

static void *softnet_seq_start(struct seq_file *seq, loff_t *pos)
{
	return softnet_get_online(pos);
}

static void *softnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return softnet_get_online(pos);
}

static void softnet_seq_stop(struct seq_file *seq, void *v)
{
}

static int softnet_seq_show(struct seq_file *seq, void *v)
{
	struct netif_rx_stats *s = v;

	seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		   s->total, s->dropped, s->time_squeeze, s->throttled,
		   s->fastroute_hit, s->fastroute_success, s->fastroute_defer,
		   s->fastroute_deferred_out,
#if 0
		   s->fastroute_latency_reduction
#else
		   s->cpu_collision
#endif
		  );
	return 0;
}

static struct seq_operations dev_seq_ops = {
	.start = dev_seq_start,
	.next  = dev_seq_next,
	.stop  = dev_seq_stop,
	.show  = dev_seq_show,
};

static int dev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dev_seq_ops);
}

static struct file_operations dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = dev_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static struct seq_operations softnet_seq_ops = {
	.start = softnet_seq_start,
	.next  = softnet_seq_next,
	.stop  = softnet_seq_stop,
	.show  = softnet_seq_show,
};

static int softnet_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &softnet_seq_ops);
}

static struct file_operations softnet_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = softnet_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

#ifdef WIRELESS_EXT
extern int wireless_proc_init(void);
#else
#define wireless_proc_init() 0
#endif

static int __init dev_proc_init(void)
{
	int rc = -ENOMEM;

	if (!proc_net_fops_create("dev", S_IRUGO, &dev_seq_fops))
		goto out;
	if (!proc_net_fops_create("softnet_stat", S_IRUGO, &softnet_seq_fops))
		goto out_dev;
	if (wireless_proc_init())
		goto out_softnet;
	rc = 0;
out:
	return rc;
out_softnet:
	proc_net_remove("softnet_stat");
out_dev:
	proc_net_remove("dev");
	goto out;
}
#else
#define dev_proc_init() 0
#endif	/* CONFIG_PROC_FS */


/**
 *	netdev_set_master	-	set up master/slave pair
 *	@slave: slave device
 *	@master: new master device
 *
 *	Changes the master device of the slave. Pass %NULL to break the
 *	bonding. The caller must hold the RTNL semaphore. On a failure
 *	a negative errno code is returned. On success the reference counts
 *	are adjusted, %RTM_NEWLINK is sent to the routing socket and the
 *	function returns zero.
 */
int netdev_set_master(struct net_device *slave, struct net_device *master)
{
	struct net_device *old = slave->master;

	ASSERT_RTNL();

	if (master) {
		if (old)
			return -EBUSY;
		dev_hold(master);
	}

	slave->master = master;
	
	synchronize_net();

	if (old)
		dev_put(old);

	if (master)
		slave->flags |= IFF_SLAVE;
	else
		slave->flags &= ~IFF_SLAVE;

	rtmsg_ifinfo(RTM_NEWLINK, slave, IFF_SLAVE);
	return 0;
}

/**
 *	dev_set_promiscuity	- update promiscuity count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove promsicuity from a device. While the count in the device
 *	remains above zero the interface remains promiscuous. Once it hits zero
 *	the device reverts back to normal filtering operation. A negative inc
 *	value is used to drop promiscuity on the device.
 */
void dev_set_promiscuity(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;

	dev->flags |= IFF_PROMISC;
	if ((dev->promiscuity += inc) == 0)
		dev->flags &= ~IFF_PROMISC;
	if (dev->flags ^ old_flags) {
		dev_mc_upload(dev);
		printk(KERN_INFO "device %s %s promiscuous mode\n",
		       dev->name, (dev->flags & IFF_PROMISC) ? "entered" :
		       					       "left");
	}
}

/**
 *	dev_set_allmulti	- update allmulti count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove reception of all multicast frames to a device. While the
 *	count in the device remains above zero the interface remains listening
 *	to all interfaces. Once it hits zero the device reverts back to normal
 *	filtering operation. A negative @inc value is used to drop the counter
 *	when releasing a resource needing all multicasts.
 */
/**
 * ֪ͨ�豸��ʼ����ֹͣ�������еĶಥ��ַ
 */
void dev_set_allmulti(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;

	dev->flags |= IFF_ALLMULTI;
	if ((dev->allmulti += inc) == 0)
		dev->flags &= ~IFF_ALLMULTI;
	if (dev->flags ^ old_flags)
		dev_mc_upload(dev);
}

unsigned dev_get_flags(const struct net_device *dev)
{
	unsigned flags;

	flags = (dev->flags & ~(IFF_PROMISC |
				IFF_ALLMULTI |
				IFF_RUNNING)) | 
		(dev->gflags & (IFF_PROMISC |
				IFF_ALLMULTI));

	if (netif_running(dev) && netif_carrier_ok(dev))
		flags |= IFF_RUNNING;

	return flags;
}
/**
 * ͨ��dev_change_flags�����޸������豸�ı�ǡ�
 */
int dev_change_flags(struct net_device *dev, unsigned flags)
{
	int ret;
	int old_flags = dev->flags;

	/*
	 *	Set the flags on our device.
	 */

	dev->flags = (flags & (IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
			       IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL |
			       IFF_AUTOMEDIA)) |
		     (dev->flags & (IFF_UP | IFF_VOLATILE | IFF_PROMISC |
				    IFF_ALLMULTI));

	/*
	 *	Load in the correct multicast list now the flags have changed.
	 */

	dev_mc_upload(dev);

	/*
	 *	Have we downed the interface. We handle IFF_UP ourselves
	 *	according to user attempts to set it, rather than blindly
	 *	setting it.
	 */

	ret = 0;
	if ((old_flags ^ flags) & IFF_UP) {	/* Bit is different  ? */
		ret = ((old_flags & IFF_UP) ? dev_close : dev_open)(dev);

		if (!ret)
			dev_mc_upload(dev);
	}

	if (dev->flags & IFF_UP &&
	    ((old_flags ^ dev->flags) &~ (IFF_UP | IFF_PROMISC | IFF_ALLMULTI |
					  IFF_VOLATILE)))
		notifier_call_chain(&netdev_chain, NETDEV_CHANGE, dev);

	if ((flags ^ dev->gflags) & IFF_PROMISC) {
		int inc = (flags & IFF_PROMISC) ? +1 : -1;
		dev->gflags ^= IFF_PROMISC;
		dev_set_promiscuity(dev, inc);
	}

	/* NOTE: order of synchronization of IFF_PROMISC and IFF_ALLMULTI
	   is important. Some (broken) drivers set IFF_PROMISC, when
	   IFF_ALLMULTI is requested not asking us and not reporting.
	 */
	if ((flags ^ dev->gflags) & IFF_ALLMULTI) {
		int inc = (flags & IFF_ALLMULTI) ? +1 : -1;
		dev->gflags ^= IFF_ALLMULTI;
		dev_set_allmulti(dev, inc);
	}

	if (old_flags ^ dev->flags)
		rtmsg_ifinfo(RTM_NEWLINK, dev, old_flags ^ dev->flags);

	return ret;
}

int dev_set_mtu(struct net_device *dev, int new_mtu)
{
	int err;

	if (new_mtu == dev->mtu)
		return 0;

	/*	MTU must be positive.	 */
	if (new_mtu < 0)
		return -EINVAL;

	if (!netif_device_present(dev))
		return -ENODEV;

	err = 0;
	if (dev->change_mtu)
		err = dev->change_mtu(dev, new_mtu);
	else
		dev->mtu = new_mtu;
	if (!err && dev->flags & IFF_UP)
		notifier_call_chain(&netdev_chain,
				    NETDEV_CHANGEMTU, dev);
	return err;
}


/*
 *	Perform the SIOCxIFxxx calls.
 */
static int dev_ifsioc(struct ifreq *ifr, unsigned int cmd)
{
	int err;
	struct net_device *dev = __dev_get_by_name(ifr->ifr_name);

	if (!dev)
		return -ENODEV;

	switch (cmd) {
		case SIOCGIFFLAGS:	/* Get interface flags */
			ifr->ifr_flags = dev_get_flags(dev);
			return 0;

		case SIOCSIFFLAGS:	/* Set interface flags */
			return dev_change_flags(dev, ifr->ifr_flags);

		case SIOCGIFMETRIC:	/* Get the metric on the interface
					   (currently unused) */
			ifr->ifr_metric = 0;
			return 0;

		case SIOCSIFMETRIC:	/* Set the metric on the interface
					   (currently unused) */
			return -EOPNOTSUPP;

		case SIOCGIFMTU:	/* Get the MTU of a device */
			ifr->ifr_mtu = dev->mtu;
			return 0;

		case SIOCSIFMTU:	/* Set the MTU of a device */
			return dev_set_mtu(dev, ifr->ifr_mtu);

		case SIOCGIFHWADDR:
			if (!dev->addr_len)
				memset(ifr->ifr_hwaddr.sa_data, 0, sizeof ifr->ifr_hwaddr.sa_data);
			else
				memcpy(ifr->ifr_hwaddr.sa_data, dev->dev_addr,
				       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
			ifr->ifr_hwaddr.sa_family = dev->type;
			return 0;

		case SIOCSIFHWADDR:
			if (!dev->set_mac_address)
				return -EOPNOTSUPP;
			if (ifr->ifr_hwaddr.sa_family != dev->type)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			err = dev->set_mac_address(dev, &ifr->ifr_hwaddr);
			if (!err)
				notifier_call_chain(&netdev_chain,
						    NETDEV_CHANGEADDR, dev);
			return err;

		case SIOCSIFHWBROADCAST:
			if (ifr->ifr_hwaddr.sa_family != dev->type)
				return -EINVAL;
			memcpy(dev->broadcast, ifr->ifr_hwaddr.sa_data,
			       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
			notifier_call_chain(&netdev_chain,
					    NETDEV_CHANGEADDR, dev);
			return 0;

		case SIOCGIFMAP:
			ifr->ifr_map.mem_start = dev->mem_start;
			ifr->ifr_map.mem_end   = dev->mem_end;
			ifr->ifr_map.base_addr = dev->base_addr;
			ifr->ifr_map.irq       = dev->irq;
			ifr->ifr_map.dma       = dev->dma;
			ifr->ifr_map.port      = dev->if_port;
			return 0;

		case SIOCSIFMAP:
			if (dev->set_config) {
				if (!netif_device_present(dev))
					return -ENODEV;
				return dev->set_config(dev, &ifr->ifr_map);
			}
			return -EOPNOTSUPP;

		case SIOCADDMULTI:
			if (!dev->set_multicast_list ||
			    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			return dev_mc_add(dev, ifr->ifr_hwaddr.sa_data,
					  dev->addr_len, 1);

		case SIOCDELMULTI:
			if (!dev->set_multicast_list ||
			    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
				return -EINVAL;
			if (!netif_device_present(dev))
				return -ENODEV;
			return dev_mc_delete(dev, ifr->ifr_hwaddr.sa_data,
					     dev->addr_len, 1);

		case SIOCGIFINDEX:
			ifr->ifr_ifindex = dev->ifindex;
			return 0;

		case SIOCGIFTXQLEN:
			ifr->ifr_qlen = dev->tx_queue_len;
			return 0;

		case SIOCSIFTXQLEN:
			if (ifr->ifr_qlen < 0)
				return -EINVAL;
			dev->tx_queue_len = ifr->ifr_qlen;
			return 0;

		case SIOCSIFNAME:
			ifr->ifr_newname[IFNAMSIZ-1] = '\0';
			return dev_change_name(dev, ifr->ifr_newname);

		/*
		 *	Unknown or private ioctl
		 */

		default:
			if ((cmd >= SIOCDEVPRIVATE &&
			    cmd <= SIOCDEVPRIVATE + 15) ||
			    cmd == SIOCBONDENSLAVE ||
			    cmd == SIOCBONDRELEASE ||
			    cmd == SIOCBONDSETHWADDR ||
			    cmd == SIOCBONDSLAVEINFOQUERY ||
			    cmd == SIOCBONDINFOQUERY ||
			    cmd == SIOCBONDCHANGEACTIVE ||
			    cmd == SIOCGMIIPHY ||
			    cmd == SIOCGMIIREG ||
			    cmd == SIOCSMIIREG ||
			    cmd == SIOCBRADDIF ||
			    cmd == SIOCBRDELIF ||
			    cmd == SIOCWANDEV) {
				err = -EOPNOTSUPP;
				if (dev->do_ioctl) {
					if (netif_device_present(dev))
						err = dev->do_ioctl(dev, ifr,
								    cmd);
					else
						err = -ENODEV;
				}
			} else
				err = -EINVAL;

	}
	return err;
}

/*
 *	This function handles all "interface"-type I/O control requests. The actual
 *	'doing' part of this is dev_ifsioc above.
 */

/**
 *	dev_ioctl	-	network device ioctl
 *	@cmd: command to issue
 *	@arg: pointer to a struct ifreq in user space
 *
 *	Issue ioctl functions to devices. This is normally called by the
 *	user space syscall interfaces but can sometimes be useful for
 *	other purposes. The return value is the return from the syscall if
 *	positive or a negative errno code on error.
 */

int dev_ioctl(unsigned int cmd, void __user *arg)
{
	struct ifreq ifr;
	int ret;
	char *colon;

	/* One special case: SIOCGIFCONF takes ifconf argument
	   and requires shared lock, because it sleeps writing
	   to user space.
	 */

	if (cmd == SIOCGIFCONF) {
		rtnl_shlock();
		ret = dev_ifconf((char __user *) arg);
		rtnl_shunlock();
		return ret;
	}
	if (cmd == SIOCGIFNAME)
		return dev_ifname((struct ifreq __user *)arg);

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	ifr.ifr_name[IFNAMSIZ-1] = 0;

	colon = strchr(ifr.ifr_name, ':');
	if (colon)
		*colon = 0;

	/*
	 *	See which interface the caller is talking about.
	 */

	switch (cmd) {
		/*
		 *	These ioctl calls:
		 *	- can be done by all.
		 *	- atomic and do not require locking.
		 *	- return a value
		 */
		case SIOCGIFFLAGS:
		case SIOCGIFMETRIC:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
		case SIOCGIFSLAVE:
		case SIOCGIFMAP:
		case SIOCGIFINDEX:
		case SIOCGIFTXQLEN:
			dev_load(ifr.ifr_name);
			read_lock(&dev_base_lock);
			ret = dev_ifsioc(&ifr, cmd);
			read_unlock(&dev_base_lock);
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		case SIOCETHTOOL:
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ethtool(&ifr);
			rtnl_unlock();
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		/*
		 *	These ioctl calls:
		 *	- require superuser power.
		 *	- require strict serialization.
		 *	- return a value
		 */
		case SIOCGMIIPHY:
		case SIOCGMIIREG:
		case SIOCSIFNAME:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ifsioc(&ifr, cmd);
			rtnl_unlock();
			if (!ret) {
				if (colon)
					*colon = ':';
				if (copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
					ret = -EFAULT;
			}
			return ret;

		/*
		 *	These ioctl calls:
		 *	- require superuser power.
		 *	- require strict serialization.
		 *	- do not return a value
		 */
		case SIOCSIFFLAGS:
		case SIOCSIFMETRIC:
		case SIOCSIFMTU:
		case SIOCSIFMAP:
		case SIOCSIFHWADDR:
		case SIOCSIFSLAVE:
		case SIOCADDMULTI:
		case SIOCDELMULTI:
		case SIOCSIFHWBROADCAST:
		case SIOCSIFTXQLEN:
		case SIOCSMIIREG:
		case SIOCBONDENSLAVE:
		case SIOCBONDRELEASE:
		case SIOCBONDSETHWADDR:
		case SIOCBONDSLAVEINFOQUERY:
		case SIOCBONDINFOQUERY:
		case SIOCBONDCHANGEACTIVE:
		case SIOCBRADDIF:
		case SIOCBRDELIF:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			dev_load(ifr.ifr_name);
			rtnl_lock();
			ret = dev_ifsioc(&ifr, cmd);
			rtnl_unlock();
			return ret;

		case SIOCGIFMEM:
			/* Get the per device memory space. We can add this but
			 * currently do not support it */
		case SIOCSIFMEM:
			/* Set the per device memory buffer space.
			 * Not applicable in our case */
		case SIOCSIFLINK:
			return -EINVAL;

		/*
		 *	Unknown or private ioctl.
		 */
		default:
			if (cmd == SIOCWANDEV ||
			    (cmd >= SIOCDEVPRIVATE &&
			     cmd <= SIOCDEVPRIVATE + 15)) {
				dev_load(ifr.ifr_name);
				rtnl_lock();
				ret = dev_ifsioc(&ifr, cmd);
				rtnl_unlock();
				if (!ret && copy_to_user(arg, &ifr,
							 sizeof(struct ifreq)))
					ret = -EFAULT;
				return ret;
			}
#ifdef WIRELESS_EXT
			/* Take care of Wireless Extensions */
			if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
				/* If command is `set a parameter', or
				 * `get the encoding parameters', check if
				 * the user has the right to do it */
				if (IW_IS_SET(cmd) || cmd == SIOCGIWENCODE) {
					if (!capable(CAP_NET_ADMIN))
						return -EPERM;
				}
				dev_load(ifr.ifr_name);
				rtnl_lock();
				/* Follow me in net/core/wireless.c */
				ret = wireless_process_ioctl(&ifr, cmd);
				rtnl_unlock();
				if (IW_IS_GET(cmd) &&
				    copy_to_user(arg, &ifr,
					    	 sizeof(struct ifreq)))
					ret = -EFAULT;
				return ret;
			}
#endif	/* WIRELESS_EXT */
			return -EINVAL;
	}
}


/**
 *	dev_new_index	-	allocate an ifindex
 *
 *	Returns a suitable unique value for a new device interface
 *	number.  The caller must hold the rtnl semaphore or the
 *	dev_base_lock to be sure it remains unique.
 */
static int dev_new_index(void)
{
	static int ifindex;
	for (;;) {
		if (++ifindex <= 0)
			ifindex = 1;
		if (!__dev_get_by_index(ifindex))
			return ifindex;
	}
}

/**
 * net_dev_init��ϵͳ�����Ƿ��Ѿ�ִ�С�
 */
static int dev_boot_phase = 1;

/* Delayed registration/unregisteration */
static DEFINE_SPINLOCK(net_todo_list_lock);
static struct list_head net_todo_list = LIST_HEAD_INIT(net_todo_list);

static inline void net_set_todo(struct net_device *dev)
{
	spin_lock(&net_todo_list_lock);
	list_add_tail(&dev->todo_list, &net_todo_list);
	spin_unlock(&net_todo_list_lock);
}

/**
 *	register_netdevice	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	Callers must hold the rtnl semaphore. You may want
 *	register_netdev() instead of this.
 *
 *	BUGS:
 *	The locking appears insufficient to guarantee two parallel registers
 *	will not get the same name.
 */
/**
 * �����豸ע��
 */
int register_netdevice(struct net_device *dev)
{
	struct hlist_head *head;
	struct hlist_node *p;
	int ret;

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/* When net_device's are persistent, this will be fatal. */
	BUG_ON(dev->reg_state != NETREG_UNINITIALIZED);

	/**
	 * net_device�Ĳ�����ĳ�ʼ����������������������
	 */
	spin_lock_init(&dev->queue_lock);
	spin_lock_init(&dev->xmit_lock);
	dev->xmit_lock_owner = -1;
#ifdef CONFIG_NET_CLS_ACT
	spin_lock_init(&dev->ingress_lock);
#endif

	/**
	 * ���ں�֧��ת������ʱ������һ��������Ҫ�����ÿ飬�����ӵ�dev->divert��������alloc_divert_blk������ʵ�ֵġ�
	 */
	ret = alloc_divert_blk(dev);
	if (ret)
		goto out;

	dev->iflink = -1;

	/* Init, if this function is available */
	/**
	 * ����豸���������ṩ�˳�ʼ������(dev->init!=NULL)����ִ�дκ������ɲο�"�����豸"һ�ڡ�
	 */
	if (dev->init) {
		ret = dev->init(dev);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out_err;
		}
	}
 
	if (!dev_valid_name(dev->name)) {
		ret = -EINVAL;
		goto out_err;
	}

	/**
	 * ��dev_new_index�������豸����һ��Ψһ��ʶ������ʶ����һ��������������ÿ��һ�����豸�ӵ�ϵͳ�м������ͻ������
	 * ��������32λ����������dev_new_index��������һ��if�Ӿ����ڻ��ƣ�����һ��if�Ӿ䴦�������ֵΪ�Ѿ�ָ�ɵ�ֵ��
	 */
	dev->ifindex = dev_new_index();
	if (dev->iflink == -1)
		dev->iflink = dev->ifindex;

	/* Check for existence of name */
	head = dev_name_hash(dev->name);
	hlist_for_each(p, head) {
		struct net_device *d
			= hlist_entry(p, struct net_device, name_hlist);
		if (!strncmp(d->name, dev->name, IFNAMSIZ)) {
			ret = -EEXIST;
 			goto out_err;
		}
 	}

	/* Fix illegal SG+CSUM combinations. */
	/**
	 * ������Ա�־�Ƿ�����Ч�����,����: 
	 *		1.  Scather/Gather-DMAû��L4(�����)Ӳ��У���֧���������õ�,��������������±���ֹ��
	 *		2.  TCP Segmentation Offload (TSO)��ҪScather/Gather-DMA�������ں��߲�֧��ʱҲ����ֹ
	 */
	if ((dev->features & NETIF_F_SG) &&
	    !(dev->features & (NETIF_F_IP_CSUM |
			       NETIF_F_NO_CSUM |
			       NETIF_F_HW_CSUM))) {
		printk("%s: Dropping NETIF_F_SG since no checksum feature.\n",
		       dev->name);
		dev->features &= ~NETIF_F_SG;
	}

	/* TSO requires that SG is present as well. */
	if ((dev->features & NETIF_F_TSO) &&
	    !(dev->features & NETIF_F_SG)) {
		printk("%s: Dropping NETIF_F_TSO since no SG feature.\n",
		       dev->name);
		dev->features &= ~NETIF_F_TSO;
	}

	/*
	 *	nil rebuild_header routine,
	 *	that should be never called and used as just bug trap.
	 */

	if (!dev->rebuild_header)
		dev->rebuild_header = default_rebuild_header;

	/*
	 *	Default initial state at registry is that the
	 *	device is present.
	 */
	/**
	 * ����dev->state�е�__LINK_STATE_PRESENT ��־ʹ�豸��ϵͳʹ���õ�(�ɼ��Ϳ���)��
	 * ���磬��һ���Ȱβ��豸���γ������ߵ�֧�ֵ�Դ�����ϵͳ�������ģʽʱ������豸��־�������
	 */
	set_bit(__LINK_STATE_PRESENT, &dev->state);

	dev->next = NULL;
	/**
	 * ��ʼ���豸���й�������������ͨ��dev_init_schedulerʵ��QoS�����й������˳��ڰ��������кʹӳ��ڶ��г����У��������˸��ְ��ڿ�ʼ��������֮ǰ����Ŷ�
	 */
	dev_init_scheduler(dev);
	/**
	 * ׷��net_device��ȫ������dev_base,���������뵽������ϣ���С�
	 * ��Ȼ�ѽṹ�ӵ�dev_base����ͷ�ܿ�,���ں�ż��Ҳ��ɨ�����������������ͬ���豸����
	 * �豸����dev_valid_name��������Ƿ�����Ч�����֡�
	 */
	write_lock_bh(&dev_base_lock);
	*dev_tail = dev;
	dev_tail = &dev->next;
	hlist_add_head(&dev->name_hlist, head);
	hlist_add_head(&dev->index_hlist, dev_index_hash(dev->ifindex));
	dev_hold(dev);
	dev->reg_state = NETREG_REGISTERING;
	write_unlock_bh(&dev_base_lock);

	/* Notify protocols, that a new device appeared. */
	/**
	 * ��netdev_chain֪ͨ��֪ͨ���ж��豸ע�����Ȥ����ϵͳ
	 */
	notifier_call_chain(&netdev_chain, NETDEV_REGISTER, dev);

	/* Finish registration after unlock */
	/**
	 * ��netdev_run_todo�������Խ���ע��ʱ����������dev->reg_state����sysfs�ļ�ϵͳע���豸��
	 */
	net_set_todo(dev);
	ret = 0;

out:
	return ret;
out_err:
	free_divert_blk(dev);
	goto out;
}

/**
 *	register_netdev	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	This is a wrapper around register_netdev that takes the rtnl semaphore
 *	and expands the device name if you passed a format string to
 *	alloc_netdev.
 */
/**
 * ע�������豸��
 */
int register_netdev(struct net_device *dev)
{
	int err;

	rtnl_lock();

	/*
	 * If the name is a format string the caller wants us to do a
	 * name allocation.
	 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto out;
	}
	
	/*
	 * Back compatibility hook. Kill this one in 2.5
	 */
	if (dev->name[0] == 0 || dev->name[0] == ' ') {
		err = dev_alloc_name(dev, "eth%d");
		if (err < 0)
			goto out;
	}

	err = register_netdevice(dev);
out:
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(register_netdev);

/*
 * netdev_wait_allrefs - wait until all references are gone.
 *
 * This is called when unregistering network devices.
 *
 * Any protocol or device that holds a reference should register
 * for netdevice notification, and cleanup and put back the
 * reference if they receive an UNREGISTER event.
 * We can get stuck here if buggy protocols don't correctly
 * call dev_put. 
 */
/**
 * unregister_netdevice����ע��������̣�����netdev_run_todo��������
 * netdev_run_todo����netdev_wait_allrefs�����ȴ����ж�net_device �ṹ�������ͷ�
 */
static void netdev_wait_allrefs(struct net_device *dev)
{
	unsigned long rebroadcast_time, warning_time;

	rebroadcast_time = warning_time = jiffies;
	/**
	 * ѭ���ȴ�������dev->refcnt ֵ����0ʱ������
	 * ������Ҫ�ȴ�����Ҫ�ǿ��ǵ���Щ��ʱ���л��ͷŶԽṹ�����á�
	 */
	while (atomic_read(&dev->refcnt) != 0) {
		/**
		 * ÿ�뷢��һ��NETDEV_UNREGISTER֪ͨ��
		 */
		if (time_after(jiffies, rebroadcast_time + 1 * HZ)) {
			rtnl_shlock();

			/* Rebroadcast unregister notification */
			notifier_call_chain(&netdev_chain,
					    NETDEV_UNREGISTER, dev);

			if (test_bit(__LINK_STATE_LINKWATCH_PENDING,
				     &dev->state)) {
				/* We must not have linkwatch events
				 * pending on unregister. If this
				 * happens, we simply run the queue
				 * unscheduled, resulting in a noop
				 * for this device.
				 */
				linkwatch_run_queue();
			}

			rtnl_shunlock();

			rebroadcast_time = jiffies;
		}

		msleep(250);

		/**
		 * ÿ10�볯����̨����һ�����档
		 */
		if (time_after(jiffies, warning_time + 10 * HZ)) {
			printk(KERN_EMERG "unregister_netdevice: "
			       "waiting for %s to become free. Usage "
			       "count = %d\n",
			       dev->name, atomic_read(&dev->refcnt));
			warning_time = jiffies;
		}
	}
}

/* The sequence is:
 *
 *	rtnl_lock();
 *	...
 *	register_netdevice(x1);
 *	register_netdevice(x2);
 *	...
 *	unregister_netdevice(y1);
 *	unregister_netdevice(y2);
 *      ...
 *	rtnl_unlock();
 *	free_netdev(y1);
 *	free_netdev(y2);
 *
 * We are invoked by rtnl_unlock() after it drops the semaphore.
 * This allows us to deal with problems:
 * 1) We can create/delete sysfs objects which invoke hotplug
 *    without deadlocking with linkwatch via keventd.
 * 2) Since we run with the RTNL semaphore not held, we can sleep
 *    safely in order to wait for the netdev refcnt to drop to zero.
 */
static DECLARE_MUTEX(net_todo_run_mutex);
void netdev_run_todo(void)
{
	struct list_head list = LIST_HEAD_INIT(list);
	int err;


	/* Need to guard against multiple cpu's getting out of order. */
	down(&net_todo_run_mutex);

	/* Not safe to do outside the semaphore.  We must not return
	 * until all unregister events invoked by the local processor
	 * have been completed (either by this todo run, or one on
	 * another cpu).
	 */
	if (list_empty(&net_todo_list))
		goto out;

	/* Snapshot list, allow later requests */
	spin_lock(&net_todo_list_lock);
	list_splice_init(&net_todo_list, &list);
	spin_unlock(&net_todo_list_lock);
		
	while (!list_empty(&list)) {
		struct net_device *dev
			= list_entry(list.next, struct net_device, todo_list);
		list_del(&dev->todo_list);

		switch(dev->reg_state) {
		case NETREG_REGISTERING:
			err = netdev_register_sysfs(dev);
			if (err)
				printk(KERN_ERR "%s: failed sysfs registration (%d)\n",
				       dev->name, err);
			dev->reg_state = NETREG_REGISTERED;
			break;

		case NETREG_UNREGISTERING:
			netdev_unregister_sysfs(dev);
			dev->reg_state = NETREG_UNREGISTERED;

			netdev_wait_allrefs(dev);

			/* paranoia */
			BUG_ON(atomic_read(&dev->refcnt));
			BUG_TRAP(!dev->ip_ptr);
			BUG_TRAP(!dev->ip6_ptr);
			BUG_TRAP(!dev->dn_ptr);


			/* It must be the very last action, 
			 * after this 'dev' may point to freed up memory.
			 */
			if (dev->destructor)
				dev->destructor(dev);
			break;

		default:
			printk(KERN_ERR "network todo '%s' but state %d\n",
			       dev->name, dev->reg_state);
			break;
		}
	}

out:
	up(&net_todo_run_mutex);
}

/**
 *	alloc_netdev - allocate network device
 *	@sizeof_priv:	size of private data to allocate space for
 *	@name:		device name format string
 *	@setup:		callback to initialize device
 *
 *	Allocates a struct net_device with private data area for driver use
 *	and performs basic initialization.
 */
/**
 * Ϊnet_device����ռ䡣
 *		 	sizeof_priv:	˽�����ݽṹ��С
 *			name:			�豸��
 *			setup:		 	���ú���,����������ڳ�ʼ��net_device�ṹ�Ĳ�����
 * ����ֵ��alloc_netdev���������net_device�Ľṹָ�룬�������ͷ���NULL��
 */
struct net_device *alloc_netdev(int sizeof_priv, const char *name,
		void (*setup)(struct net_device *))
{
	void *p;
	struct net_device *dev;
	int alloc_size;

	/* ensure 32-byte alignment of both the device and private area */
	alloc_size = (sizeof(*dev) + NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST;
	alloc_size += sizeof_priv + NETDEV_ALIGN_CONST;

	p = kmalloc(alloc_size, GFP_KERNEL);
	if (!p) {
		printk(KERN_ERR "alloc_dev: Unable to allocate device.\n");
		return NULL;
	}
	memset(p, 0, alloc_size);

	dev = (struct net_device *)
		(((long)p + NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST);
	dev->padded = (char *)dev - (char *)p;

	if (sizeof_priv)
		dev->priv = netdev_priv(dev);

	setup(dev);
	strcpy(dev->name, name);
	return dev;
}
EXPORT_SYMBOL(alloc_netdev);

/**
 *	free_netdev - free network device
 *	@dev: device
 *
 *	This function does the last stage of destroying an allocated device 
 * 	interface. The reference to the device object is released.  
 *	If this is the last reference then it will be freed.
 */
void free_netdev(struct net_device *dev)
{
#ifdef CONFIG_SYSFS
	/*  Compatiablity with error handling in drivers */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		kfree((char *)dev - dev->padded);
		return;
	}

	BUG_ON(dev->reg_state != NETREG_UNREGISTERED);
	dev->reg_state = NETREG_RELEASED;

	/* will free via class release */
	class_device_put(&dev->class_dev);
#else
	kfree((char *)dev - dev->padded);
#endif
}
 
/* Synchronize with packet receive processing. */
void synchronize_net(void) 
{
	might_sleep();
	synchronize_kernel();
}

/**
 *	unregister_netdevice - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables. On success 0 is returned, on a failure
 *	a negative errno code is returned.
 *
 *	Callers must hold the rtnl semaphore.  You may want
 *	unregister_netdev() instead of this.
 */
/**
 * ע�������豸
 */
int unregister_netdevice(struct net_device *dev)
{
	struct net_device *d, **dp;

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/* Some devices call without registering for initialization unwind. */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		printk(KERN_DEBUG "unregister_netdevice: device %s/%p never "
				  "was registered\n", dev->name, dev);
		return -ENODEV;
	}

	BUG_ON(dev->reg_state != NETREG_REGISTERED);

	/* If device is running, close it first. */
	/**
	 * ����豸û�б���ֹ����������dev_close��ֹ��
	 */
	if (dev->flags & IFF_UP)
		dev_close(dev);

	/* And unlink it from device chain. */
	/**
	 * net_deviceʵ����ȫ������dev_base���Ƴ���ͬʱ��"net_device�ṹ��֯"һ���н��ܵ�������ϣ��Ҳ���Ƴ���
	 * ע��������������ֹ�ں���ϵͳʹ���豸��������Ȼӵ��ָ��net_device�ṹ��ָ�롣
	 * �����net_device�ṹʹ�����ü����Ի�ȡ�ṹ���ж������õ�ԭ��
	 */
	for (dp = &dev_base; (d = *dp) != NULL; dp = &d->next) {
		if (d == dev) {
			write_lock_bh(&dev_base_lock);
			hlist_del(&dev->name_hlist);
			hlist_del(&dev->index_hlist);
			if (dev_tail == &dev->next)
				dev_tail = dp;
			*dp = d->next;
			write_unlock_bh(&dev_base_lock);
			break;
		}
	}
	if (!d) {
		printk(KERN_ERR "unregister net_device: '%s' not found\n",
		       dev->name);
		return -ENODEV;
	}

	dev->reg_state = NETREG_UNREGISTERING;

	synchronize_net();

	/* Shutdown queueing discipline. */
	/**
	 * ��dev_shutdown�����ͷ��������豸��صĶ��й���ʵ����
	 */
	dev_shutdown(dev);

	
	/* Notify protocols, that we are about to destroy
	   this device. They should clean all the things.
	*/
	/**
	 * NETDEV_UNREGISTER֪ͨ���͵�netdev_chain֪ͨ��ʹ�����ں����֪�����¼�������
	 * �û��ռ��յ�ע��֪ͨ�����磬��һ�����ڷ���internet����˫������ϵͳ�У����֪ͨ�����������ڶ���������
	 */
	notifier_call_chain(&netdev_chain, NETDEV_UNREGISTER, dev);
	
	/*
	 *	Flush the multicast chain
	 */
	/**
	 * �ͷ��������ӵ�net_device�ṹ�����ݿ顣
	 * ���磬dev_mc_discard�����ͷŶಥ����dev->mc_list��free_divert_blk�����ͷ�ת���飬�ȵȡ�
	 */
	dev_mc_discard(dev);

	/**
	 * ��register_netdevice�е�dev->init������κ������ڴ˶�����dev->uninit����
	 */
	if (dev->uninit)
		dev->uninit(dev);

	/* Notifier chain MUST detach us from master device. */
	/**
	 * �󶨵������������һ���豸����ƭ������Ϊһ�������ľ������⹦�ܵ������豸��
	 * ����Щ�豸֮�䣬����֮һ����ѡ����Ϊ���豸����Ϊ�����������ڵ������ɫ��
	 * ����������Ե�ԭ�򣬱��Ƴ����豸Ӧ���ͷ����еĶ����豸�����ã�����������£�dev->master �ǿս���һ�� bug��
	 */
	BUG_TRAP(!dev->master);

	free_divert_blk(dev);

	/* Finish processing unregister after unlock */
	/**
	 * net_set_todo��������ʹnet_run_todo����ע������
	 * net_run_todo������sysfs��ע���豸��������dev->reg_state ΪNETREG_UNREGISTERED���ȵ����е����ö��ͷź󣬵���dev->destructor����ע�����̡�
	 */
	net_set_todo(dev);

	synchronize_net();

	/**
	 * dev_put�����������ü���
	 */
	dev_put(dev);
	return 0;
}

/**
 *	unregister_netdev - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables. On success 0 is returned, on a failure
 *	a negative errno code is returned.
 *
 *	This is just a wrapper for unregister_netdevice that takes
 *	the rtnl semaphore.  In general you want to use this and not
 *	unregister_netdevice.
 */
void unregister_netdev(struct net_device *dev)
{
	rtnl_lock();
	unregister_netdevice(dev);
	rtnl_unlock();
}

EXPORT_SYMBOL(unregister_netdev);

#ifdef CONFIG_HOTPLUG_CPU
static int dev_cpu_callback(struct notifier_block *nfb,
			    unsigned long action,
			    void *ocpu)
{
	struct sk_buff **list_skb;
	struct net_device **list_net;
	struct sk_buff *skb;
	unsigned int cpu, oldcpu = (unsigned long)ocpu;
	struct softnet_data *sd, *oldsd;

	if (action != CPU_DEAD)
		return NOTIFY_OK;

	local_irq_disable();
	cpu = smp_processor_id();
	sd = &per_cpu(softnet_data, cpu);
	oldsd = &per_cpu(softnet_data, oldcpu);

	/* Find end of our completion_queue. */
	list_skb = &sd->completion_queue;
	while (*list_skb)
		list_skb = &(*list_skb)->next;
	/* Append completion queue from offline CPU. */
	*list_skb = oldsd->completion_queue;
	oldsd->completion_queue = NULL;

	/* Find end of our output_queue. */
	list_net = &sd->output_queue;
	while (*list_net)
		list_net = &(*list_net)->next_sched;
	/* Append output queue from offline CPU. */
	*list_net = oldsd->output_queue;
	oldsd->output_queue = NULL;

	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_enable();

	/* Process offline CPU's input_pkt_queue */
	while ((skb = __skb_dequeue(&oldsd->input_pkt_queue)))
		netif_rx(skb);

	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */


/*
 *	Initialize the DEV module. At boot time this walks the device list and
 *	unhooks any devices that fail to initialise (normally hardware not
 *	present) and leaves us with a valid list of present and active devices.
 *
 */

/*
 *       This is called single threaded during boot, so no need
 *       to take the rtnl semaphore.
 */
/**
 * �����豸���ʼ�������������һЩ����Ҫ�Ĺ��ܣ������������ƣ�ÿ��CPU��������еȹ��ܵĳ�ʼ����
 * ���������豸��������ǰִ�С�
 */
static int __init net_dev_init(void)
{
	int i, rc = -ENOMEM;

	BUG_ON(!dev_boot_phase);

	/**
	 * net_random_init��ʼ��ÿ��cpu���������飬��Щ������ net_random ���������ʱʹ�á�
	 */
	net_random_init();

	/**
	 * ����ں˱���ѡ���а�����/proc�ļ�ϵͳ������ȱʡ���ã���dev_proc_init��dev_mcast_init�ͻ���/procĿ¼������һЩ�ļ�
	 */
	if (dev_proc_init())
		goto out;

	/**
	 * netdev_sysfs_initע������������sysfs��
	 * ��������/sys/class/netĿ¼�������Ŀ¼�£���ῴ��ÿ����ע�������豸����Ŀ¼��
	 * ��ЩĿ¼�°����ܶ��ļ�����Щ�ļ�ԭ���Ƿ���/procĿ¼�¡�
	 */
	if (netdev_sysfs_init())
		goto out;

	INIT_LIST_HEAD(&ptype_all);
	/**
	 * ��ʼ�����紦�������� ptype_base����Щ������������·�ֽ���յ��İ���
	 */
	for (i = 0; i < 16; i++) 
		INIT_LIST_HEAD(&ptype_base[i]);

	for (i = 0; i < ARRAY_SIZE(dev_name_head); i++)
		INIT_HLIST_HEAD(&dev_name_head[i]);

	for (i = 0; i < ARRAY_SIZE(dev_index_head); i++)
		INIT_HLIST_HEAD(&dev_index_head[i]);

	/*
	 *	Initialise the packet receive queues.
	 */
	/**
	 * ��ʼ��cpu��ص����ݽṹ����Щ�ṹ�������������ж�ʹ�á�
	 */
	for (i = 0; i < NR_CPUS; i++) {
		struct softnet_data *queue;

		queue = &per_cpu(softnet_data, i);
		skb_queue_head_init(&queue->input_pkt_queue);
		queue->throttle = 0;
		queue->cng_level = 0;
		queue->avg_blog = 10; /* arbitrary non-zero */
		queue->completion_queue = NULL;
		INIT_LIST_HEAD(&queue->poll_list);
		set_bit(__LINK_STATE_START, &queue->backlog_dev.state);
		/**
		 * backlog_dev������ķ�NAPI�豸��
		 */
		queue->backlog_dev.weight = weight_p;
		queue->backlog_dev.poll = process_backlog;
		atomic_set(&queue->backlog_dev.refcnt, 1);
	}

#ifdef OFFLINE_SAMPLE
	/**
	 * ���������OFFLINE_SAMPLE��ǣ��ں˻ᶨ������һ�������ռ��豸���г��ȵ�ͳ����Ϣ��
	 * ����������£�net_dev_init��ҪΪ��������һ����ʱ����ʹ�����Զ������С�
	 */
	samp_timer.expires = jiffies + (10 * HZ);
	add_timer(&samp_timer);
#endif

	/**
	 * �޸�dev_boot_phase��ֵΪ0����ʾ�������Ѿ�ִ�й��ˡ�
	 * ÿ��ע���豸ʱ����Ҫ������ֵ�Ƿ�Ϊ0.��ȷ��������ȷʵ�Ѿ�ִ�й��ˡ�
	 * ����Ҫ��Ϊ�˼��ݾɵ��������롣��2.6�У���ʵ����ȷ����������������ִ�С�
	 */
	dev_boot_phase = 0;

	open_softirq(NET_TX_SOFTIRQ, net_tx_action, NULL);
	open_softirq(NET_RX_SOFTIRQ, net_rx_action, NULL);

	/**
	 * ��֪ͨ������ע��һ���ص����������ڽ��� CPU ���Ȳ���¼���
	 * ����Ļص�������dev_cpu_callback����ǰΨһ������¼���CPU�ر��¼���
	 * ����յ�֪ͨ��CPU��������еİ���ȡ����������netif_rx��
	 */
	hotcpu_notifier(dev_cpu_callback, 0);
	/**
	 * dst_init��ʼ��Э���޹ص�Ŀ�Ļ��棨DST��
	 */
	dst_init();
	dev_mcast_init();
	rc = 0;
out:
	return rc;
}
/**
 * subsys_initcallȷ���˸ú�������ϵͳ��ʼ�������������豸����֮ǰ���С�
 */
subsys_initcall(net_dev_init);

EXPORT_SYMBOL(__dev_get_by_index);
EXPORT_SYMBOL(__dev_get_by_name);
EXPORT_SYMBOL(__dev_remove_pack);
EXPORT_SYMBOL(__skb_linearize);
EXPORT_SYMBOL(dev_add_pack);
EXPORT_SYMBOL(dev_alloc_name);
EXPORT_SYMBOL(dev_close);
EXPORT_SYMBOL(dev_get_by_flags);
EXPORT_SYMBOL(dev_get_by_index);
EXPORT_SYMBOL(dev_get_by_name);
EXPORT_SYMBOL(dev_ioctl);
EXPORT_SYMBOL(dev_open);
EXPORT_SYMBOL(dev_queue_xmit);
EXPORT_SYMBOL(dev_remove_pack);
EXPORT_SYMBOL(dev_set_allmulti);
EXPORT_SYMBOL(dev_set_promiscuity);
EXPORT_SYMBOL(dev_change_flags);
EXPORT_SYMBOL(dev_set_mtu);
EXPORT_SYMBOL(free_netdev);
EXPORT_SYMBOL(netdev_boot_setup_check);
EXPORT_SYMBOL(netdev_set_master);
EXPORT_SYMBOL(netdev_state_change);
EXPORT_SYMBOL(netif_receive_skb);
EXPORT_SYMBOL(netif_rx);
EXPORT_SYMBOL(register_gifconf);
EXPORT_SYMBOL(register_netdevice);
EXPORT_SYMBOL(register_netdevice_notifier);
EXPORT_SYMBOL(skb_checksum_help);
EXPORT_SYMBOL(synchronize_net);
EXPORT_SYMBOL(unregister_netdevice);
EXPORT_SYMBOL(unregister_netdevice_notifier);
EXPORT_SYMBOL(net_enable_timestamp);
EXPORT_SYMBOL(net_disable_timestamp);

#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
EXPORT_SYMBOL(br_handle_frame_hook);
#endif

#ifdef CONFIG_KMOD
EXPORT_SYMBOL(dev_load);
#endif

EXPORT_PER_CPU_SYMBOL(softnet_data);
