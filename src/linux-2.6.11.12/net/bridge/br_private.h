/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_private.h,v 1.7 2001/12/24 00:59:55 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/if_bridge.h>

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

#define BR_PORT_BITS	10
/**
 * ÿ�������豸���֧�ֵĶ˿�������
 */
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

/**
 * ����ID��������ݽṹû�з�ӳ 802.1t�ı仯��
 */
struct bridge_id
{
	/**
	 * �������ȼ���
	 */
	unsigned char	prio[2];
	/**
	 * ����MAC��ַ��
	 */
	unsigned char	addr[6];
};

/**
 * MAC��ַ��
 */
struct mac_addr
{
	unsigned char	addr[6];
};

/**
 * ת�����ݿ���Ŀ��
 * ÿһ�����Ž��е�ַѧϰʱ��ÿһ��MAC��ַ����һ����������Ŀ��
 */
struct net_bridge_fdb_entry
{
	/**
	 * ���ڽ����ݽṹ����hash��ĳ�ͻ�����С�
	 */
	struct hlist_node		hlist;
	/**
	 * ���Ŷ˿ڡ�
	 */
	struct net_bridge_port		*dst;
	union {
		struct list_head	age_list;
		/**
		 * ��ʹ��RCU��ɾ�������ݽṹʱʹ�á�
		 */
		struct rcu_head		rcu;
	} u;
	/**
	 * ���ü�����
	 */
	atomic_t			use_count;
	/**
	 * �ϻ�ʱ�ӡ�
	 */
	unsigned long			ageing_timer;
	/**
	 * MAC��ַ���������ڲ�ѯ�Ĺؼ��ֶΡ�
	 */
	mac_addr			addr;
	/**
	 * ������־Ϊ1ʱ����ʾMAC��ַ�Ǳ����豸��һ�����á�
	 */
	unsigned char			is_local;
	/**
	 * ������־Ϊ1ʱ����ʾMAC��ַ�Ǿ�̬�ģ����ᳬ�ڡ����б��ص�ַ�����ó�1.
	 */
	unsigned char			is_static;
};

/**
 * ���Ŷ˿ڡ�
 */
struct net_bridge_port
{
	/**
	 * �����豸
	 */
	struct net_bridge		*br;
	/**
	 * �󶨵��豸��
	 */
	struct net_device		*dev;
	/**
	 * ���ڽ����ݽṹ����hash��ĳ�ͻ�����С�
	 */
	struct list_head		list;

	/* STP */
	/**
	 * �˿����ȼ���
	 */
	u8				priority;
	/**
	 * �˿�״̬����Чֵ��include/linux/if_bridge.h�У���Щö��ֵ����ʽ����BR_STATE_XXX��
	 */
	u8				state;
	/**
	 * �˿ںš�
	 */
	u16				port_no;
	/**
	 * �������־������ʱ�������ڶ˿��Ϸ��͵�����BPDU������TCA��־��
	 */
	unsigned char			topology_change_ack;
	/**
	 * ��һ������BPDU���ڱ�HOLDʱ���������ȴ�����ʱ���ñ�־����1��
	 */
	unsigned char			config_pending;
	/**
	 * �˿�ID����br_make_port_id���㣬��priority��port_no���ɡ�
	 */
	port_id				port_id;
	/**
	 * �˿��Ͻ��յ����������BPDU�����ȼ���������br_record_config_configuration���ڽ��յ���ÿһ������BPDU���и��¡�
	 */
	port_id				designated_port;
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	/**
	 * �˿�·�����ȡ�
	 */
	u32				path_cost;
	u32				designated_cost;

	/**
	 * �˿�ʱ�ӡ�
	 */
	struct timer_list		forward_delay_timer;
	struct timer_list		hold_timer;
	struct timer_list		message_age_timer;
	/**
	 * ���������豸�ļ���
	 */
	struct kobject			kobj;
	/**
	 * ����ͨ��RCU���ư�ȫ���ͷ����ݽṹ��
	 */
	struct rcu_head			rcu;
};

/**
 * �������ŵ���Ϣ��
 * ������ݽṹ����ӵ�һ��net_device���ݽṹ���Դ���������豸��˵����������˽�����ݽ����������豸����⡣
 */
struct net_bridge
{
	/**
	 * ���������޸�net_bridge���ݽṹ��������port_list�е�ĳ���˿ڡ�Ҫ����ֻ�����ʣ�ֻ��Ҫ�򵥵�ʹ��rcu_read_lock��rcu_read_unlock���ɡ�
	 */
	spinlock_t			lock;
	/**
	 * ���Ŷ˿��б�.
	 */
	struct list_head		port_list;
	/**
	 * �����豸��
	 */
	struct net_device		*dev;
	struct net_device_stats		statistics;
	/**
	 * ��ת�����ݿ��Ԫ�ؽ��д��ж�д���ʡ�
	 * ֻ�����ʿ��Լ򵥵�ʹ��rcu_read_lock��rcu_read_unlock��
	 */
	spinlock_t			hash_lock;
	/**
	 * ת�����ݿ⡣
	 */
	struct hlist_head		hash[BR_HASH_SIZE];
	/**
	 * �������Ѿ����ٱ�ʹ�á�
	 */
	struct list_head		age_list;

	/* STP */
	/**
	 * ����ID��
	 */
	bridge_id			designated_root;
	/**
	 * ����ID��
	 */
	bridge_id			bridge_id;
	/**
	 * �����ŵ����·���ĳ��ȡ�
	 */
	u32				root_path_cost;
	/**
	 * ����ʱ�ӡ���Щֵ�ɸ������ã����ڽ��յ�����BPDUʱ����br_record_config_timeout_values�����ڱ��ء�
	 */
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	/**
	 * �������õ�����ʱ�ӣ����ڸ�����ʹ�á�
	 */
	unsigned long			bridge_max_age;
	/**
	 * ת�����ݿ��е�Ԫ�ص�����ϻ�ʱ�䡣
	 */
	unsigned long			ageing_time;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;

	/**
	 * ���˿ںš�
	 */
	u16				root_port;
	/**
	 * ����ñ�־�����ã���ô���ž�������STP��
	 */
	unsigned char			stp_enabled;
	/**
	 * �����һ���Ӹ��˿ڽ��յ�������BPDU����TC��־ʱ���ñ�־�����á�
	 * ���ñ�־������ʱ�����з��͵�����BPDUҲ��������TC��־��
	 */
	unsigned char			topology_change;
	/**
	 * �����˱仯�¼�����⵽ʱ�����øñ�־��
	 */
	unsigned char			topology_change_detected;

	/**
	 * ����ʱ�ӡ�
	 */
	struct timer_list		hello_timer;
	struct timer_list		tcn_timer;
	struct timer_list		topology_change_timer;
	/**
	 * ת�����ݿ���������ʱ�ӡ�
	 */
	struct timer_list		gc_timer;
	/**
	 * ���������豸�ļ���
	 */
	struct kobject			ifobj;
};

extern struct notifier_block br_device_notifier;
extern const unsigned char bridge_ula[6];

/* called under bridge lock */
/**
 * br_is_root_bridge����ָ�����豸�Ƿ��Ǹ����豸��
 */
static inline int br_is_root_bridge(const struct net_bridge *br)
{
	return !memcmp(&br->bridge_id, &br->designated_root, 8);
}


/* br_device.c */
extern void br_dev_setup(struct net_device *dev);
extern int br_dev_xmit(struct sk_buff *skb, struct net_device *dev);

/* br_fdb.c */
extern void br_fdb_init(void);
extern void br_fdb_fini(void);
extern void br_fdb_changeaddr(struct net_bridge_port *p,
			      const unsigned char *newaddr);
extern void br_fdb_cleanup(unsigned long arg);
extern void br_fdb_delete_by_port(struct net_bridge *br,
			   struct net_bridge_port *p);
extern struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
						 const unsigned char *addr);
extern struct net_bridge_fdb_entry *br_fdb_get(struct net_bridge *br,
					       unsigned char *addr);
extern void br_fdb_put(struct net_bridge_fdb_entry *ent);
extern int br_fdb_fillbuf(struct net_bridge *br, void *buf, 
			  unsigned long count, unsigned long off);
extern int br_fdb_insert(struct net_bridge *br,
			 struct net_bridge_port *source,
			 const unsigned char *addr,
			 int is_local);

/* br_forward.c */
extern void br_deliver(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_dev_queue_push_xmit(struct sk_buff *skb);
extern void br_forward(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_forward_finish(struct sk_buff *skb);
extern void br_flood_deliver(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);
extern void br_flood_forward(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);

/* br_if.c */
extern int br_add_bridge(const char *name);
extern int br_del_bridge(const char *name);
extern void br_cleanup_bridges(void);
extern int br_add_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_del_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_min_mtu(const struct net_bridge *br);

/* br_input.c */
extern int br_handle_frame_finish(struct sk_buff *skb);
extern int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb);

/* br_ioctl.c */
extern int br_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
extern int br_ioctl_deviceless_stub(unsigned int cmd, void __user *arg);

/* br_netfilter.c */
extern int br_netfilter_init(void);
extern void br_netfilter_fini(void);

/* br_stp.c */
extern void br_log_state(const struct net_bridge_port *p);
extern struct net_bridge_port *br_get_port(struct net_bridge *br,
				    	   u16 port_no);
extern void br_init_port(struct net_bridge_port *p);
extern void br_become_designated_port(struct net_bridge_port *p);

/* br_stp_if.c */
extern void br_stp_enable_bridge(struct net_bridge *br);
extern void br_stp_disable_bridge(struct net_bridge *br);
extern void br_stp_enable_port(struct net_bridge_port *p);
extern void br_stp_disable_port(struct net_bridge_port *p);
extern void br_stp_recalculate_bridge_id(struct net_bridge *br);
extern void br_stp_set_bridge_priority(struct net_bridge *br,
				       u16 newprio);
extern void br_stp_set_port_priority(struct net_bridge_port *p,
				     u8 newprio);
extern void br_stp_set_path_cost(struct net_bridge_port *p,
				 u32 path_cost);
extern ssize_t br_show_bridge_id(char *buf, const struct bridge_id *id);

/* br_stp_bpdu.c */
extern int br_stp_handle_bpdu(struct sk_buff *skb);

/* br_stp_timer.c */
extern void br_stp_timer_init(struct net_bridge *br);
extern void br_stp_port_timer_init(struct net_bridge_port *p);
extern unsigned long br_timer_value(const struct timer_list *timer);

#ifdef CONFIG_SYSFS
/* br_sysfs_if.c */
extern int br_sysfs_addif(struct net_bridge_port *p);
extern void br_sysfs_removeif(struct net_bridge_port *p);
extern void br_sysfs_freeif(struct net_bridge_port *p);

/* br_sysfs_br.c */
extern int br_sysfs_addbr(struct net_device *dev);
extern void br_sysfs_delbr(struct net_device *dev);

#else

#define br_sysfs_addif(p)	(0)
#define br_sysfs_removeif(p)	do { } while(0)
#define br_sysfs_freeif(p)	kfree(p)
#define br_sysfs_addbr(dev)	(0)
#define br_sysfs_delbr(dev)	do { } while(0)
#endif /* CONFIG_SYSFS */

#endif
