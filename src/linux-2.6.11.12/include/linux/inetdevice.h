#ifndef _LINUX_INETDEVICE_H
#define _LINUX_INETDEVICE_H

#ifdef __KERNEL__

#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>

/**
 * �ýṹ�����ֶ�ͨ��/proc/sys/net/ipv4/conf��������ڵ��������豸����Ϊ��
 * ÿ���豸����һ��ʵ�������⻹��һ���Ǵ洢Ĭ��ֵ�ģ�ipv4_devconf_dflt��
 */
struct ipv4_devconf
{
	int	accept_redirects;
	int	send_redirects;
	int	secure_redirects;
	int	shared_media;
	int	accept_source_route;
	int	rp_filter;
	int	proxy_arp;
	int	bootp_relay;
	int	log_martians;
	/**
	 * ��Ϊ��0ʱ���Ϳ������豸ת��������
	 */
	int	forwarding;
	int	mc_forwarding;
	int	tag;
	/**
	 * ��һ̨�����ж��NIC���ӵ�ͬһ��LAN����������ͬһ��IP������ʱ�����ѡ����Կ���һ���ӿ��Ƿ����ARPOP_REQUEST����Ӧ��
	 * ���ѡ����ʹ����IPԴ·��ѡ��������к����á�
	 * �����ø�ѡ���ֻ�����ں�֪����ε��﷢�ͷ���IP��ַ������ֻ�е��﷢�ͷ�IP��ַ���豸�ǽ������ARPOP_REQUEST�����豸ʱ���ں˲Żᴦ���������
	 */
	int     arp_filter;
	/**
	 * ��ѡ�����ͨ��proc���ã�������ARP����ʱ��ѡ���ĸ�IP��ַ�ŵ�ARP����ͷ�С���ֵ����Ϊ:
	 *		0 (Default)	:		�κα���IP��ַ�����ԡ�
	 * 		1:					������ܣ�ѡ���Ŀ�ĵ�ַλ��ͬһ�������ڵĵ�ַ������ʹ�ü���2�Ľ����
	 *		2:					����ʹ������ַ��
	 */
	int	arp_announce;
	/**
	 * �Ƿ���Զ�ĳЩARP�������Ӧ����Ҫ����������������棬������ȡֵ����:
	 *		0 (Default):		���κα��ص�ַ��ARP����Ӧ��.
	 *		1:					���Ŀ��IP�������յ�ARP����Ľӿ��ϣ���Ӧ��
	 *		2:					��1���ƣ�����ԴIP�����Ŀ��IP����ͬһ��������
	 *		3:					���Ŀ��IP��scope���Ǳ���ַ��������Ӧ��
	 *		4-7:				����.
	 *		8:					��Ӧ��.
	 *		>8:					δ֪��ֵ����������.
	 */
	int	arp_ignore;
	/**
	 * ��ARP�������������NIC����ͬһ�㲥����ʱ���������ARP����������⡣
	 * ͨ�����ֶθ���ARP����������ͬmedium_id��NIC����ͬһ�㲥�򣬶�ARP������Ҫ�����⴦��
	 *		-1:				ARP�����Ѿ��رա�
	 *		0 (default):	Medium ID�����Ѿ����ر�.
	 *		>0:				�Ϸ���medium ID.
	 */
	int	medium_id;
	int	no_xfrm;
	int	no_policy;
	int	force_igmp_version;
	void	*sysctl;
};

extern struct ipv4_devconf ipv4_devconf;

/**
 * in_device�ṹ�洢��һ�������豸������Ipv4��ص��������ݣ������û���ifconfig��ip���������ı�����ýṹͨ��net_device->ip_ptr���ӵ�net_device�ṹ��
 */
struct in_device
{
	/**
	 * ָ�������net_device�ṹ��ָ�롣
	 */
	struct net_device	*dev;
	/**
	 * ���ü���ֵ�����Ǵ��ֶ�Ϊ0����ô�˽ṹ�Ͳ��ܱ��ͷš�
	 */
	atomic_t		refcnt;
	/**
	 * ���ֶ��趨ʱ���ǰ��豸��ʾ��������������ڼ��һЩ��������磬��Ŀ�޷������٣��������ü�����Ϊ0�����ǣ����ٶ����Ѿ������ˡ�
	 */
	int			dead;
	/**
	 * �豸�������õ�IPV4��ַ�б�
	 * In_ifaddrʵ���ᰴ��Χ���򣨷�Χ������ǰ�棩������ͬ��Χ��Ԫ���򰴵�ַ����������Ҫ��ַ��ǰ�棩��
	 */
	struct in_ifaddr	*ifa_list;	/* IP ifaddr chain		*/
	rwlock_t		mc_list_lock;
	/**
	 * �豸�Ķಥ���ã���ifa_list�Ķಥ����
	 */
	struct ip_mc_list	*mc_list;	/* IP multicast filter chain    */
	spinlock_t		mc_tomb_lock;
	struct ip_mc_list	*mc_tomb;
	unsigned long		mr_v1_seen;
	/**
	 * ��IGMPЭ�����õ�ʱ����Լ�¼IGMP���Ľ��ա�
	 */
	unsigned long		mr_v2_seen;
	unsigned long		mr_maxdelay;
	unsigned char		mr_qrv;
	unsigned char		mr_gq_running;
	unsigned char		mr_ifc_count;
	struct timer_list	mr_gq_timer;	/* general query timer */
	struct timer_list	mr_ifc_timer;	/* interface change timer */

	struct neigh_parms	*arp_parms;
	/**
	 * IP��������Ϣ��
	 */
	struct ipv4_devconf	cnf;
	/**
	 * ��RCU����ʹ��ʵ�ֻ��⡣����ɵĹ�������ͬ��һ�㡣
	 */
	struct rcu_head		rcu_head;
};

#define IN_DEV_FORWARD(in_dev)		((in_dev)->cnf.forwarding)
#define IN_DEV_MFORWARD(in_dev)		(ipv4_devconf.mc_forwarding && (in_dev)->cnf.mc_forwarding)
#define IN_DEV_RPFILTER(in_dev)		(ipv4_devconf.rp_filter && (in_dev)->cnf.rp_filter)
#define IN_DEV_SOURCE_ROUTE(in_dev)	(ipv4_devconf.accept_source_route && (in_dev)->cnf.accept_source_route)
#define IN_DEV_BOOTP_RELAY(in_dev)	(ipv4_devconf.bootp_relay && (in_dev)->cnf.bootp_relay)

#define IN_DEV_LOG_MARTIANS(in_dev)	(ipv4_devconf.log_martians || (in_dev)->cnf.log_martians)
#define IN_DEV_PROXY_ARP(in_dev)	(ipv4_devconf.proxy_arp || (in_dev)->cnf.proxy_arp)
#define IN_DEV_SHARED_MEDIA(in_dev)	(ipv4_devconf.shared_media || (in_dev)->cnf.shared_media)
#define IN_DEV_TX_REDIRECTS(in_dev)	(ipv4_devconf.send_redirects || (in_dev)->cnf.send_redirects)
#define IN_DEV_SEC_REDIRECTS(in_dev)	(ipv4_devconf.secure_redirects || (in_dev)->cnf.secure_redirects)
#define IN_DEV_IDTAG(in_dev)		((in_dev)->cnf.tag)
#define IN_DEV_MEDIUM_ID(in_dev)	((in_dev)->cnf.medium_id)

#define IN_DEV_RX_REDIRECTS(in_dev) \
	((IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects && (in_dev)->cnf.accept_redirects)) \
	 || (!IN_DEV_FORWARD(in_dev) && \
	  (ipv4_devconf.accept_redirects || (in_dev)->cnf.accept_redirects)))

#define IN_DEV_ARPFILTER(in_dev)	(ipv4_devconf.arp_filter || (in_dev)->cnf.arp_filter)
/**
 * ��ȡproc���ã����������ö�IPʱ��ѡ����һ��IP��ΪARP�����ԴIP�ֶΡ�
 */
#define IN_DEV_ARP_ANNOUNCE(in_dev)	(max(ipv4_devconf.arp_announce, (in_dev)->cnf.arp_announce))
#define IN_DEV_ARP_IGNORE(in_dev)	(max(ipv4_devconf.arp_ignore, (in_dev)->cnf.arp_ignore))

/**
 * ���ڽӿ�������һ��Ipv4��ַʱ���ں˻Ὠ��һ��in_ifaddr�ṹ��
 */
struct in_ifaddr
{
	/**
	 * ָ����������һ��Ԫ�ص�ָ�롣������������豸�������õ����е�ַ��
	 */
	struct in_ifaddr	*ifa_next;
	/**
	 * ָ�������in_device�ṹ��ָ�롣
	 */
	struct in_device	*ifa_dev;
	/**
	 * ��RCU����ʹ����ʵ�ֻ��⣬����������
	 */
	struct rcu_head		rcu_head;
	/**
	 * �������ֶε�ֵȡ���ڸõ�ַ�Ƿ�ָ�ɸ�һ������ӿڡ�
	 * ����ǣ�ifa_local��ifa_address��������ı��غ�Զ�̵�ַ��
	 * ������ǣ��������������Ǳ��ؽӿڵĵ�ַ��
	 */
	u32			ifa_local;
	u32			ifa_address;
	/**
	 * ifa_mask���Ǻ͸õ�ַ������������롣
	 */
	u32			ifa_mask;
	/**
	 * �㲥��ַ��
	 */
	u32			ifa_broadcast;
	/**
	 * ѡ����ַ��
	 */
	u32			ifa_anycast;
	/**
	 * ��ַ�ķ�Χ��Ĭ����RT_SCOPE_UNIVERSE���൱��0���������ֶ�ͨ�����ifconfig/ip�����ֵ��
	 * ������Ҳ����ѡ��ͬ��ֵ����Ҫ��������λ�ڷ�Χ127.x.x.x��ĵ�ַ���䷶ΧΪRT_SCOPE_HOST��
	 */
	unsigned char		ifa_scope;
	/**
	 * ���ܵ�IFA_F_XXXλ��־������include/linux/rtnetlink.h�С�������IPV4���õ�һ����־��
	 *		IFA_F_SECONDARY����һ���µ�ַ����һ̨�豸ʱ��������豸������һ����ַ������ͬ�������磬��õ�ַ�ͻᱻ��Ϊ��Ҫ��ַ��
	 *		������־��IPV6ʹ�á�
	 */
	unsigned char		ifa_flags;
	/**
	 * ���ɴ������������Ŀ��
	 */
	unsigned char		ifa_prefixlen;
	char			ifa_label[IFNAMSIZ];
};

extern int register_inetaddr_notifier(struct notifier_block *nb);
extern int unregister_inetaddr_notifier(struct notifier_block *nb);

extern struct net_device 	*ip_dev_find(u32 addr);
extern int		inet_addr_onlink(struct in_device *in_dev, u32 a, u32 b);
extern int		devinet_ioctl(unsigned int cmd, void __user *);
extern void		devinet_init(void);
extern struct in_device *inetdev_init(struct net_device *dev);
extern struct in_device	*inetdev_by_index(int);
extern u32		inet_select_addr(const struct net_device *dev, u32 dst, int scope);
extern u32		inet_confirm_addr(const struct net_device *dev, u32 dst, u32 local, int scope);
extern struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, u32 prefix, u32 mask);
extern void		inet_forward_change(void);

/**
 * ����һ��IP��ַ��һ�����������inet_ifa_match����ָ���ĵڶ���IP��ַ�Ƿ�������ͬ�����ڡ�
 * �˺���ͨ��Ҳ���ڷ������Ҫ��ַ���Լ����ָ����IP��ַ�Ƿ�������Щ������������֮һ��
 */
static __inline__ int inet_ifa_match(u32 addr, struct in_ifaddr *ifa)
{
	return !((addr^ifa->ifa_address)&ifa->ifa_mask);
}

/*
 *	Check if a mask is acceptable.
 */
 
static __inline__ int bad_mask(u32 mask, u32 addr)
{
	if (addr & (mask = ~mask))
		return 1;
	mask = ntohl(mask);
	if (mask & (mask+1))
		return 1;
	return 0;
}

/**
 * �������������in_device�ṹ�����������in_ifaddrʵ����
 * for_primary_ifaֻ������Ҫ��ַ����for_ifa�������е�ַ��
 */
#define for_primary_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa && !(ifa->ifa_flags&IFA_F_SECONDARY); ifa = ifa->ifa_next)

/**
 * �������������in_device�ṹ�����������in_ifaddrʵ����
 * for_primary_ifaֻ������Ҫ��ַ����for_ifa�������е�ַ��
 */
#define for_ifa(in_dev)	{ struct in_ifaddr *ifa; \
  for (ifa = (in_dev)->ifa_list; ifa; ifa = ifa->ifa_next)


#define endfor_ifa(in_dev) }

/**
 * ��ȡһ��NIC�豸���õ�IP���ÿ顣
 */
static __inline__ struct in_device *
in_dev_get(const struct net_device *dev)
{
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = dev->ip_ptr;
	if (in_dev)
		atomic_inc(&in_dev->refcnt);
	rcu_read_unlock();
	return in_dev;
}

static __inline__ struct in_device *
__in_dev_get(const struct net_device *dev)
{
	return (struct in_device*)dev->ip_ptr;
}

extern void in_dev_finish_destroy(struct in_device *idev);

static inline void in_dev_put(struct in_device *idev)
{
	if (atomic_dec_and_test(&idev->refcnt))
		in_dev_finish_destroy(idev);
}

#define __in_dev_put(idev)  atomic_dec(&(idev)->refcnt)
#define in_dev_hold(idev)   atomic_inc(&(idev)->refcnt)

#endif /* __KERNEL__ */

/**
 * ������������(netmask)����ɵ�1����Ŀ��inet_make_mask�Ϳɽ���������������롣
 * ���磬����ֵ24�ͻ������������255.255.255.0��
 */
static __inline__ __u32 inet_make_mask(int logmask)
{
	if (logmask)
		return htonl(~((1<<(32-logmask))-1));
	return 0;
}

/**
 * inet_mask_len�᷵��ʮ��������������1����Ŀ������ 255.255.0.0�᷵��16��
 */
static __inline__ int inet_mask_len(__u32 mask)
{
	if (!(mask = ntohl(mask)))
		return 0;
	return 32 - ffz(~mask);
}


#endif /* _LINUX_INETDEVICE_H */
