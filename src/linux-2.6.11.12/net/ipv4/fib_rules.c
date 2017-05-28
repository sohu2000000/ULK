/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: policy rules.
 *
 * Version:	$Id: fib_rules.c,v 1.17 2001/10/31 21:55:54 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Fixes:
 * 		Rani Assaf	:	local_rule cannot be deleted
 *		Marc Boucher	:	routing by fwmark
 */

#include <linux/config.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/ip_fib.h>

#define FRprintk(a...)

/**
 * ��ʾ�ɲ���·��ѡ����Ӧ·�ɱ�Ĺ���
 */
struct fib_rule
{
	/**
	 * ����Щfib_rule�ṹ���ӵ�һ����������fib_ruleʵ����ȫ�������ڡ�
	 */
	struct fib_rule *r_next;
	/**
	 * ���ü����������ü����ĵ�������fib_lookup������ֻ�ڲ���·�ɰ�ĺ����У��н��еģ��������Ϊʲô��ÿ��·�ɲ��ҳɹ���������Ҫ����fib_res_put���ݼ������ü�������
	 */
	atomic_t	r_clntref;
	/**
	 * ·�ɹ�������ȼ���
	 * ������Ա����IPROUTE2��������һ������ʱ������ʹ�ùؼ���priority��preference��order�����á�
	 * ���û����ȷ���ã��ں�Ϊ�����һ�����ȼ�����ֵ���û���ӵ����һ����������ȼ�С1
	 */
	u32		r_preference;
	/**
	 * ·�ɱ��ʶ����Χ��0��255��
	 */
	unsigned char	r_table;
	/**
	 * ���ֶ������ȡֵ����include/linux/rtnetlink.h�ļ��ж����rtm_typeö��ֵ��RTN_UNICAST�ȣ���
	 * ���û�����һ������ʱ��ʹ��type�ؼ������趨���ֶΡ�����û�û����ȷ���ã�IPROUTE2����ӹ���ʱ���ø��ֶε�ֵΪRTN_UNICAST��
	 */
	unsigned char	r_action;
	/**
	 * Ŀ��IP��ַ��ԴIP��ַ�ĳ��ȣ���λΪ���ء����Ǳ����ڼ���r_srcmask��r_dstmask������������ֶ�δ����ʼ��������Ϊ0��
	 */
	unsigned char	r_dst_len;
	unsigned char	r_src_len;
	/**
	 * ��ʾֻ�дӸ�IP��ַ������������ɵ�Դ���緢�͵ı��Ĳ��ܱ����ܡ�
	 */
	u32		r_src;
	u32		r_srcmask;
	/**
	 * ��ʾֻ�����IP��ַ������������ɵ�Ŀ�����緢�ͱ��ġ�
	 */
	u32		r_dst;
	u32		r_dstmask;
	/**
	 * ���ֶ��������û��ռ�ؼ���nat��map-to�����ã���·��NATʵ�ִ���ʹ�á����ڲ���֧��·��NAT�����Ը��ֶ�Ҳ���ٱ�ʹ�á�
	 */
	u32		r_srcmap;
	/**
	 * һ���־����ǰδʹ�á�
	 */
	u8		r_flags;
	/**
	 * IPͷ�е�TOS�ֶΡ��������ֶε�ԭ���ǹ���Ķ����п��԰���һ������������������IPͷ����TOS�ֶΡ�
	 */
	u8		r_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	/**
	 * ���ں˱���֧��"ʹ��Netfilter MARKֵ��Ϊ·��key"����ʱ�����Ը��ݷ���ǽ��ǩ���������
	 * ���ֶ��ǹ���Ա����һ�����Թ���ʱ����fwmark�ؼ���ָ���ı�ǩ��
	 */
	u32		r_fwmark;
#endif
	/**
	 * r_ifname�ǲ���Ӧ�õ��豸�����ơ�
	 * ����r_ifname���ں˿��Եõ���ص�net_deviceʵ��������ʵ����ifindex�ֶο�����r_ifindex�С�
	 * r_ifindexֵȡ-1��ʾ��ֹ�ù���
	 */
	int		r_ifindex;
#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * ����realm.
	 * Դrealm��Ŀ��realm����8����ֵ����ΧΪ0��255��������r_tclassid�У����Ƕ�ռ��16���ء�
	 * ������Դrealmʱ���������ڸ�16����λ��������Ŀ��realmʱ���������ڵ�16����λ
	 */
	__u32		r_tclassid;
#endif
	char		r_ifname[IFNAMSIZ];
	/**
	 * ��һ���������ʱ���ֶ�Ϊ0��
	 * ������inet_rtm_delruleɾ������ʱ���ֶα�����Ϊ1��
	 * ÿ������fib_rule_putɾ����fib_rule���ݽṹ��һ������ʱ���ݼ����ü����������ü���Ϊ0ʱ��Ҫ�ͷŸýṹ��
	 * ����ʱ���r_deadû�����ã����ʾ������ĳ�ִ���
	 */
	int		r_dead;
};

static struct fib_rule default_rule = {
	.r_clntref =	ATOMIC_INIT(2),
	.r_preference =	0x7FFF,
	.r_table =	RT_TABLE_DEFAULT,
	.r_action =	RTN_UNICAST,
};

static struct fib_rule main_rule = {
	.r_next =	&default_rule,
	.r_clntref =	ATOMIC_INIT(2),
	.r_preference =	0x7FFE,
	.r_table =	RT_TABLE_MAIN,
	.r_action =	RTN_UNICAST,
};

static struct fib_rule local_rule = {
	.r_next =	&main_rule,
	.r_clntref =	ATOMIC_INIT(2),
	.r_table =	RT_TABLE_LOCAL,
	.r_action =	RTN_UNICAST,
};

/**
 * ����·�������������ȼ�˳��������С�
 * ��ʹ�û�û�������κι���fib_rulesҲ��������ȱʡ��fib_ruleʵ��:local_rule,main_rule,default_rule
 */
static struct fib_rule *fib_rules = &local_rule;
/**
 * ���rwlock����������Ϊfib_rule���ݽṹ��fib_rulesȫ������
 */
static DEFINE_RWLOCK(fib_rules_lock);

int inet_rtm_delrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtattr **rta = arg;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct fib_rule *r, **rp;
	int err = -ESRCH;

	for (rp=&fib_rules; (r=*rp) != NULL; rp=&r->r_next) {
		if ((!rta[RTA_SRC-1] || memcmp(RTA_DATA(rta[RTA_SRC-1]), &r->r_src, 4) == 0) &&
		    rtm->rtm_src_len == r->r_src_len &&
		    rtm->rtm_dst_len == r->r_dst_len &&
		    (!rta[RTA_DST-1] || memcmp(RTA_DATA(rta[RTA_DST-1]), &r->r_dst, 4) == 0) &&
		    rtm->rtm_tos == r->r_tos &&
#ifdef CONFIG_IP_ROUTE_FWMARK
		    (!rta[RTA_PROTOINFO-1] || memcmp(RTA_DATA(rta[RTA_PROTOINFO-1]), &r->r_fwmark, 4) == 0) &&
#endif
		    (!rtm->rtm_type || rtm->rtm_type == r->r_action) &&
		    (!rta[RTA_PRIORITY-1] || memcmp(RTA_DATA(rta[RTA_PRIORITY-1]), &r->r_preference, 4) == 0) &&
		    (!rta[RTA_IIF-1] || rtattr_strcmp(rta[RTA_IIF-1], r->r_ifname) == 0) &&
		    (!rtm->rtm_table || (r && rtm->rtm_table == r->r_table))) {
			err = -EPERM;
			if (r == &local_rule)
				break;

			write_lock_bh(&fib_rules_lock);
			*rp = r->r_next;
			r->r_dead = 1;
			write_unlock_bh(&fib_rules_lock);
			fib_rule_put(r);
			err = 0;
			break;
		}
	}
	return err;
}

/* Allocate new unique table id */

static struct fib_table *fib_empty_table(void)
{
	int id;

	for (id = 1; id <= RT_TABLE_MAX; id++)
		if (fib_tables[id] == NULL)
			return __fib_new_table(id);
	return NULL;
}

void fib_rule_put(struct fib_rule *r)
{
	if (atomic_dec_and_test(&r->r_clntref)) {
		if (r->r_dead)
			kfree(r);
		else
			printk("Freeing alive rule %p\n", r);
	}
}

int inet_rtm_newrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct rtattr **rta = arg;
	struct rtmsg *rtm = NLMSG_DATA(nlh);
	struct fib_rule *r, *new_r, **rp;
	unsigned char table_id;

	if (rtm->rtm_src_len > 32 || rtm->rtm_dst_len > 32 ||
	    (rtm->rtm_tos & ~IPTOS_TOS_MASK))
		return -EINVAL;

	if (rta[RTA_IIF-1] && RTA_PAYLOAD(rta[RTA_IIF-1]) > IFNAMSIZ)
		return -EINVAL;

	table_id = rtm->rtm_table;
	if (table_id == RT_TABLE_UNSPEC) {
		struct fib_table *table;
		if (rtm->rtm_type == RTN_UNICAST) {
			if ((table = fib_empty_table()) == NULL)
				return -ENOBUFS;
			table_id = table->tb_id;
		}
	}

	new_r = kmalloc(sizeof(*new_r), GFP_KERNEL);
	if (!new_r)
		return -ENOMEM;
	memset(new_r, 0, sizeof(*new_r));
	if (rta[RTA_SRC-1])
		memcpy(&new_r->r_src, RTA_DATA(rta[RTA_SRC-1]), 4);
	if (rta[RTA_DST-1])
		memcpy(&new_r->r_dst, RTA_DATA(rta[RTA_DST-1]), 4);
	if (rta[RTA_GATEWAY-1])
		memcpy(&new_r->r_srcmap, RTA_DATA(rta[RTA_GATEWAY-1]), 4);
	new_r->r_src_len = rtm->rtm_src_len;
	new_r->r_dst_len = rtm->rtm_dst_len;
	new_r->r_srcmask = inet_make_mask(rtm->rtm_src_len);
	new_r->r_dstmask = inet_make_mask(rtm->rtm_dst_len);
	new_r->r_tos = rtm->rtm_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	if (rta[RTA_PROTOINFO-1])
		memcpy(&new_r->r_fwmark, RTA_DATA(rta[RTA_PROTOINFO-1]), 4);
#endif
	new_r->r_action = rtm->rtm_type;
	new_r->r_flags = rtm->rtm_flags;
	if (rta[RTA_PRIORITY-1])
		memcpy(&new_r->r_preference, RTA_DATA(rta[RTA_PRIORITY-1]), 4);
	new_r->r_table = table_id;
	if (rta[RTA_IIF-1]) {
		struct net_device *dev;
		rtattr_strlcpy(new_r->r_ifname, rta[RTA_IIF-1], IFNAMSIZ);
		new_r->r_ifindex = -1;
		dev = __dev_get_by_name(new_r->r_ifname);
		if (dev)
			new_r->r_ifindex = dev->ifindex;
	}
#ifdef CONFIG_NET_CLS_ROUTE
	if (rta[RTA_FLOW-1])
		memcpy(&new_r->r_tclassid, RTA_DATA(rta[RTA_FLOW-1]), 4);
#endif

	rp = &fib_rules;
	if (!new_r->r_preference) {
		r = fib_rules;
		if (r && (r = r->r_next) != NULL) {
			rp = &fib_rules->r_next;
			if (r->r_preference)
				new_r->r_preference = r->r_preference - 1;
		}
	}

	while ( (r = *rp) != NULL ) {
		if (r->r_preference > new_r->r_preference)
			break;
		rp = &r->r_next;
	}

	new_r->r_next = r;
	atomic_inc(&new_r->r_clntref);
	write_lock_bh(&fib_rules_lock);
	*rp = new_r;
	write_unlock_bh(&fib_rules_lock);
	return 0;
}

#ifdef CONFIG_NET_CLS_ROUTE
/**
 * ��һ��fib_rule���ݽṹ����ȡr_tclassid�ֶΡ�
 * ��Ϊfib_lookup���صĽ���ڰ���һ��ָ��ָ��ƥ���fib_ruleʵ���������ڲ���֮��ʹ��fib_rules_tclass����ȡƥ�����
 */
u32 fib_rules_tclass(struct fib_result *res)
{
	if (res->r)
		return res->r->r_tclassid;
	return 0;
}
#endif


static void fib_rules_detach(struct net_device *dev)
{
	struct fib_rule *r;

	for (r=fib_rules; r; r=r->r_next) {
		if (r->r_ifindex == dev->ifindex) {
			write_lock_bh(&fib_rules_lock);
			r->r_ifindex = -1;
			write_unlock_bh(&fib_rules_lock);
		}
	}
}

static void fib_rules_attach(struct net_device *dev)
{
	struct fib_rule *r;

	for (r=fib_rules; r; r=r->r_next) {
		if (r->r_ifindex == -1 && strcmp(dev->name, r->r_ifname) == 0) {
			write_lock_bh(&fib_rules_lock);
			r->r_ifindex = dev->ifindex;
			write_unlock_bh(&fib_rules_lock);
		}
	}
}

/**
 * ���ں�֧�ֲ���·��ʱ��fib_lookup��
 */
int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	int err;
	struct fib_rule *r, *policy;
	struct fib_table *tb;

	u32 daddr = flp->fl4_dst;
	u32 saddr = flp->fl4_src;

FRprintk("Lookup: %u.%u.%u.%u <- %u.%u.%u.%u ",
	NIPQUAD(flp->fl4_dst), NIPQUAD(flp->fl4_src));
	read_lock(&fib_rules_lock);
	/**
	 * һ����һ���ر���·�ɲ��ԣ�ֱ�����ҵ���·�ɱ���ƥ��Ĳ��Ի򵽴��������β����û���ҵ��κ�ƥ�䡣
	 */
	for (r = fib_rules; r; r=r->r_next) {
		if (((saddr^r->r_src) & r->r_srcmask) ||
		    ((daddr^r->r_dst) & r->r_dstmask) ||
		    (r->r_tos && r->r_tos != flp->fl4_tos) ||
#ifdef CONFIG_IP_ROUTE_FWMARK
		    (r->r_fwmark && r->r_fwmark != flp->fl4_fwmark) ||
#endif
		    (r->r_ifindex && r->r_ifindex != flp->iif))
			continue;

FRprintk("tb %d r %d ", r->r_table, r->r_action);
		/**
		 * �����ҵ�ƥ�����ʱ���������Ķ��������ڲ������͡�
		 */
		switch (r->r_action) {
		/**
		 * ���Զ���RTN_UNICAST������tb_lookup�����ң���ʵ�����ǵ���fn_hash_lookup�������ú������Է��ض��ֽ����
		 */
		case RTN_UNICAST:
			policy = r;
			break;
		/**
		 * �ر�أ����Զ���RTN_UNREACHABLE��RTN_BLACKHOLE��RTN_PROHIBIT������һ������fib_lookup�ĵ��÷����ݸô���ֵ��������Ӧ��ICMP��Ϣ��
		 */
		case RTN_UNREACHABLE:
			read_unlock(&fib_rules_lock);
			return -ENETUNREACH;
		default:
		case RTN_BLACKHOLE:
			read_unlock(&fib_rules_lock);
			return -EINVAL;
		case RTN_PROHIBIT:
			read_unlock(&fib_rules_lock);
			return -EACCES;
		}

		if ((tb = fib_get_table(r->r_table)) == NULL)
			continue;
		/**
		 * ���е����˵����Ҫ�ڲ���·�ɱ������������·���ˡ�
		 */
		err = tb->tb_lookup(tb, flp, res);
		if (err == 0) {
			/**
			 * �����ҳɹ�ʱ��res->r����ʼ��Ϊƥ����ԡ�
			 */
			res->r = policy;
			if (policy)
				atomic_inc(&policy->r_clntref);
			read_unlock(&fib_rules_lock);
			return 0;
		}
		/**
		 * ·�ɲ���ʧ�ܡ�
		 */
		if (err < 0 && err != -EAGAIN) {
			read_unlock(&fib_rules_lock);
			return err;
		}
		/**
		 * ������ʧ��ʱ�������������Ϊ-EAGAIN��fib_lookup������ѭ���ڲ��Ҳ��ԡ�
		 * ���ظô���ֵ��ԭ������Ϊ��fn_hash_lookup���ҵ���ƥ��·����صĶ�������ΪRTN_THROW
		 */
	}
FRprintk("FAILURE\n");
	read_unlock(&fib_rules_lock);
	return -ENETUNREACH;
}

/**
 * ���ں�֧�ֲ���·��ʱ��ѡ��ȱʡ���ء�
 */
void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * ��֧�ֲ���·��ʱѡ��ȱʡ·���벻֧�ֲ���·��ʱѡ��Ĺ���������ͬ��
	 * Ψһ����������fib_select_default����ƥ����ԣ�res->r�����õ�ʹ�õ�·�ɱ�
	 */
	if (res->r && res->r->r_action == RTN_UNICAST &&
	    FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK) {
		struct fib_table *tb;
		if ((tb = fib_get_table(res->r->r_table)) != NULL)
			tb->tb_select_default(tb, flp, res);
	}
}

static int fib_rules_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	if (event == NETDEV_UNREGISTER)
		fib_rules_detach(dev);
	else if (event == NETDEV_REGISTER)
		fib_rules_attach(dev);
	return NOTIFY_DONE;
}


static struct notifier_block fib_rules_notifier = {
	.notifier_call =fib_rules_event,
};

static __inline__ int inet_fill_rule(struct sk_buff *skb,
				     struct fib_rule *r,
				     struct netlink_callback *cb)
{
	struct rtmsg *rtm;
	struct nlmsghdr  *nlh;
	unsigned char	 *b = skb->tail;

	nlh = NLMSG_PUT(skb, NETLINK_CREDS(cb->skb)->pid, cb->nlh->nlmsg_seq, RTM_NEWRULE, sizeof(*rtm));
	rtm = NLMSG_DATA(nlh);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = r->r_dst_len;
	rtm->rtm_src_len = r->r_src_len;
	rtm->rtm_tos = r->r_tos;
#ifdef CONFIG_IP_ROUTE_FWMARK
	if (r->r_fwmark)
		RTA_PUT(skb, RTA_PROTOINFO, 4, &r->r_fwmark);
#endif
	rtm->rtm_table = r->r_table;
	rtm->rtm_protocol = 0;
	rtm->rtm_scope = 0;
	rtm->rtm_type = r->r_action;
	rtm->rtm_flags = r->r_flags;

	if (r->r_dst_len)
		RTA_PUT(skb, RTA_DST, 4, &r->r_dst);
	if (r->r_src_len)
		RTA_PUT(skb, RTA_SRC, 4, &r->r_src);
	if (r->r_ifname[0])
		RTA_PUT(skb, RTA_IIF, IFNAMSIZ, &r->r_ifname);
	if (r->r_preference)
		RTA_PUT(skb, RTA_PRIORITY, 4, &r->r_preference);
	if (r->r_srcmap)
		RTA_PUT(skb, RTA_GATEWAY, 4, &r->r_srcmap);
#ifdef CONFIG_NET_CLS_ROUTE
	if (r->r_tclassid)
		RTA_PUT(skb, RTA_FLOW, 4, &r->r_tclassid);
#endif
	nlh->nlmsg_len = skb->tail - b;
	return skb->len;

nlmsg_failure:
rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}

int inet_dump_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
	int idx;
	int s_idx = cb->args[0];
	struct fib_rule *r;

	read_lock(&fib_rules_lock);
	for (r=fib_rules, idx=0; r; r = r->r_next, idx++) {
		if (idx < s_idx)
			continue;
		if (inet_fill_rule(skb, r, cb) < 0)
			break;
	}
	read_unlock(&fib_rules_lock);
	cb->args[0] = idx;

	return skb->len;
}

/**
 * ����·�ɵĳ�ʼ����
 */
void __init fib_rules_init(void)
{
	register_netdevice_notifier(&fib_rules_notifier);
}
