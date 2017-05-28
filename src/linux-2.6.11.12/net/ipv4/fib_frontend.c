/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: FIB frontend.
 *
 * Version:	$Id: fib_frontend.c,v 1.26 2001/10/31 21:55:54 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
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
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <net/arp.h>
#include <net/ip_fib.h>

#define FFprint(a...) printk(KERN_DEBUG a)

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define RT_TABLE_MIN RT_TABLE_MAIN

/**
 * �ں˽������ص�ַ��·�ɱ�����ڸñ��У���������ص����ε�ַ�Լ����ι㲥��ַ��·�ɱ��
 */
struct fib_table *ip_fib_local_table;
/**
 * ����������·�ɱ�������û����õľ�̬·�ɱ��·��Э�����ɵĶ�̬·�ɱ�������ڸñ��ڡ�
 */
struct fib_table *ip_fib_main_table;

#else

#define RT_TABLE_MIN 1
/**
 * ��֧�ֲ���·������£�ָ��255��·�ɱ��ָ�뱻�洢��fib_tables������
 */
struct fib_table *fib_tables[RT_TABLE_MAX+1];

struct fib_table *__fib_new_table(int id)
{
	struct fib_table *tb;

	tb = fib_hash_init(id);
	if (!tb)
		return NULL;
	fib_tables[id] = tb;
	return tb;
}


#endif /* CONFIG_IP_MULTIPLE_TABLES */

/**
 * ɨ��ip_fib_main_table��ip_fib_local_table·�ɱ�ɾ�����е�������RTNH_F_DEAD ��־��fib_info�ṹ��
 * ����ɾ��fib_info�ṹ��Ҳɾ���������fib_alias�ṹ��
 * ��һ��fib_nodeʵ��������fib_alias�ṹʱ����fib_nodeʵ��Ҳ��ɾ����
 * ���ں�֧�ֶ�·��ʱ��fib_flushɨ�����е�·�ɱ�
 */
static void fib_flush(void)
{
	int flushed = 0;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_table *tb;
	int id;

	for (id = RT_TABLE_MAX; id>0; id--) {
		if ((tb = fib_get_table(id))==NULL)
			continue;
		flushed += tb->tb_flush(tb);
	}
#else /* CONFIG_IP_MULTIPLE_TABLES */
	flushed += ip_fib_main_table->tb_flush(ip_fib_main_table);
	flushed += ip_fib_local_table->tb_flush(ip_fib_local_table);
#endif /* CONFIG_IP_MULTIPLE_TABLES */

	if (flushed)
		rt_cache_flush(-1);
}

/*
 *	Find the first device with a given source address.
 */

struct net_device * ip_dev_find(u32 addr)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result res;
	struct net_device *dev = NULL;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif

	if (!ip_fib_local_table ||
	    ip_fib_local_table->tb_lookup(ip_fib_local_table, &fl, &res))
		return NULL;
	if (res.type != RTN_LOCAL)
		goto out;
	dev = FIB_RES_DEV(res);

	if (dev)
		dev_hold(dev);
out:
	fib_res_put(&res);
	return dev;
}
/**
 * ȷ��һ��L3��ַ��һ���������㲥�Ͷಥ��ַ��
 */
unsigned inet_addr_type(u32 addr)
{
	struct flowi		fl = { .nl_u = { .ip4_u = { .daddr = addr } } };
	struct fib_result	res;
	unsigned ret = RTN_BROADCAST;

	if (ZERONET(addr) || BADCLASS(addr))
		return RTN_BROADCAST;
	if (MULTICAST(addr))
		return RTN_MULTICAST;

#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r = NULL;
#endif
	
	if (ip_fib_local_table) {
		ret = RTN_UNICAST;
		if (!ip_fib_local_table->tb_lookup(ip_fib_local_table,
						   &fl, &res)) {
			ret = res.type;
			fib_res_put(&res);
		}
	}
	return ret;
}

/* Given (packet source, input interface) and optional (dst, oif, tos):
   - (main) check, that source is valid i.e. not broadcast or our local
     address.
   - figure out what "logical" interface this packet arrived
     and calculate "specific destination" address.
   - check, that packet arrived from expected physical interface.
 */

/**
 * �Դ�һ�������豸���յ��ı��ĵ�ԴIP��ַ���飬�����ͼ��IP��ƭ��
 * ���һ�Ҫ��ʹ�ܷǶԳ�·������£�ȷ�����ĵ�ԴIP��ַͨ���ñ��Ľ��սӿ��ǿɴ��
 */
int fib_validate_source(u32 src, u32 dst, u8 tos, int oif,
			struct net_device *dev, u32 *spec_dst, u32 *itag)
{
	struct in_device *in_dev;
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = src,
					.saddr = dst,
					.tos = tos } },
			    .iif = oif };
	struct fib_result res;
	int no_addr, rpf;
	int ret;

	no_addr = rpf = 0;
	rcu_read_lock();
	in_dev = __in_dev_get(dev);
	if (in_dev) {
		no_addr = in_dev->ifa_list == NULL;
		rpf = IN_DEV_RPFILTER(in_dev);
	}
	rcu_read_unlock();

	if (in_dev == NULL)
		goto e_inval;

	if (fib_lookup(&fl, &res))
		goto last_resort;
	if (res.type != RTN_UNICAST)
		goto e_inval_res;
	*spec_dst = FIB_RES_PREFSRC(res);
	fib_combine_itag(itag, &res);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (FIB_RES_DEV(res) == dev || res.fi->fib_nhs > 1)
#else
	if (FIB_RES_DEV(res) == dev)
#endif
	{
		ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		fib_res_put(&res);
		return ret;
	}
	fib_res_put(&res);
	if (no_addr)
		goto last_resort;
	if (rpf)
		goto e_inval;
	fl.oif = dev->ifindex;

	ret = 0;
	if (fib_lookup(&fl, &res) == 0) {
		if (res.type == RTN_UNICAST) {
			*spec_dst = FIB_RES_PREFSRC(res);
			ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
		}
		fib_res_put(&res);
	}
	return ret;

last_resort:
	if (rpf)
		goto e_inval;
	*spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
	*itag = 0;
	return 0;

e_inval_res:
	fib_res_put(&res);
e_inval:
	return -EINVAL;
}

#ifndef CONFIG_IP_NOSIOCRT

/*
 *	Handle IP routing ioctl calls. These are used to manipulate the routing tables
 */
 
int ip_rt_ioctl(unsigned int cmd, void __user *arg)
{
	int err;
	struct kern_rta rta;
	struct rtentry  r;
	struct {
		struct nlmsghdr nlh;
		struct rtmsg	rtm;
	} req;

	switch (cmd) {
	case SIOCADDRT:		/* Add a route */
	case SIOCDELRT:		/* Delete a route */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&r, arg, sizeof(struct rtentry)))
			return -EFAULT;
		rtnl_lock();
		err = fib_convert_rtentry(cmd, &req.nlh, &req.rtm, &rta, &r);
		if (err == 0) {
			if (cmd == SIOCDELRT) {
				struct fib_table *tb = fib_get_table(req.rtm.rtm_table);
				err = -ESRCH;
				if (tb)
					err = tb->tb_delete(tb, &req.rtm, &rta, &req.nlh, NULL);
			} else {
				struct fib_table *tb = fib_new_table(req.rtm.rtm_table);
				err = -ENOBUFS;
				if (tb)
					err = tb->tb_insert(tb, &req.rtm, &rta, &req.nlh, NULL);
			}
			if (rta.rta_mx)
				kfree(rta.rta_mx);
		}
		rtnl_unlock();
		return err;
	}
	return -EINVAL;
}

#else

int ip_rt_ioctl(unsigned int cmd, void *arg)
{
	return -EINVAL;
}

#endif

static int inet_check_attr(struct rtmsg *r, struct rtattr **rta)
{
	int i;

	for (i=1; i<=RTA_MAX; i++) {
		struct rtattr *attr = rta[i-1];
		if (attr) {
			if (RTA_PAYLOAD(attr) < 4)
				return -EINVAL;
			if (i != RTA_MULTIPATH && i != RTA_METRICS)
				rta[i-1] = (struct rtattr*)RTA_DATA(attr);
		}
	}
	return 0;
}

int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_table * tb;
	struct rtattr **rta = arg;
	struct rtmsg *r = NLMSG_DATA(nlh);

	if (inet_check_attr(r, rta))
		return -EINVAL;

	tb = fib_get_table(r->rtm_table);
	if (tb)
		return tb->tb_delete(tb, r, (struct kern_rta*)rta, nlh, &NETLINK_CB(skb));
	return -ESRCH;
}

int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct fib_table * tb;
	struct rtattr **rta = arg;
	struct rtmsg *r = NLMSG_DATA(nlh);

	if (inet_check_attr(r, rta))
		return -EINVAL;

	tb = fib_new_table(r->rtm_table);
	if (tb)
		return tb->tb_insert(tb, r, (struct kern_rta*)rta, nlh, &NETLINK_CB(skb));
	return -ENOBUFS;
}

int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb)
{
	int t;
	int s_t;
	struct fib_table *tb;

	if (NLMSG_PAYLOAD(cb->nlh, 0) >= sizeof(struct rtmsg) &&
	    ((struct rtmsg*)NLMSG_DATA(cb->nlh))->rtm_flags&RTM_F_CLONED)
		return ip_rt_dump(skb, cb);

	s_t = cb->args[0];
	if (s_t == 0)
		s_t = cb->args[0] = RT_TABLE_MIN;

	for (t=s_t; t<=RT_TABLE_MAX; t++) {
		if (t < s_t) continue;
		if (t > s_t)
			memset(&cb->args[1], 0, sizeof(cb->args)-sizeof(cb->args[0]));
		if ((tb = fib_get_table(t))==NULL)
			continue;
		if (tb->tb_dump(tb, skb, cb) < 0) 
			break;
	}

	cb->args[0] = t;

	return skb->len;
}

/* Prepare and feed intra-kernel routing request.
   Really, it should be netlink message, but :-( netlink
   can be not configured, so that we feed it directly
   to fib engine. It is legal, because all events occur
   only when netlink is already locked.
 */

static void fib_magic(int cmd, int type, u32 dst, int dst_len, struct in_ifaddr *ifa)
{
	struct fib_table * tb;
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	rtm;
	} req;
	struct kern_rta rta;

	memset(&req.rtm, 0, sizeof(req.rtm));
	memset(&rta, 0, sizeof(rta));

	if (type == RTN_UNICAST)
		tb = fib_new_table(RT_TABLE_MAIN);
	else
		tb = fib_new_table(RT_TABLE_LOCAL);

	if (tb == NULL)
		return;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = cmd;
	req.nlh.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_APPEND;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 0;

	req.rtm.rtm_dst_len = dst_len;
	req.rtm.rtm_table = tb->tb_id;
	req.rtm.rtm_protocol = RTPROT_KERNEL;
	req.rtm.rtm_scope = (type != RTN_LOCAL ? RT_SCOPE_LINK : RT_SCOPE_HOST);
	req.rtm.rtm_type = type;

	rta.rta_dst = &dst;
	rta.rta_prefsrc = &ifa->ifa_local;
	rta.rta_oif = &ifa->ifa_dev->dev->ifindex;

	if (cmd == RTM_NEWROUTE)
		tb->tb_insert(tb, &req.rtm, &rta, &req.nlh, NULL);
	else
		tb->tb_delete(tb, &req.rtm, &rta, &req.nlh, NULL);
}

/**
 * ������һ����IPʱ������·����ص��¼���
 */
static void fib_add_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *prim = ifa;
	u32 mask = ifa->ifa_mask;
	u32 addr = ifa->ifa_local;
	u32 prefix = ifa->ifa_address&mask;

	/**
	 * ���һ���ڶ�IP��ַ
	 */
	if (ifa->ifa_flags&IFA_F_SECONDARY) {
		/**
		 * �ڸ��豸�ϱ��������ͬһ���Σ�prefix���ڵ�һ����IP��ַ�������������IP��ַ�����ڣ���ô���õ��������ò��ܹ���Ч��
		 */
		prim = inet_ifa_byprefix(in_dev, prefix, mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_add_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	/**
	 * ��ӵ�IP��ַ�ı���·�ɡ�
	 * ��ʹ��ʱ�豸û��ʹ�ܣ�Ҳ���԰�ȫ����ӱ��ص�ַ·�ɣ���Ϊ��ʹ�����豸ʹ�ܺ���ӱ��ص�ַҲ����ɹ�����������ظ���
	 */
	fib_magic(RTM_NEWROUTE, RTN_LOCAL, addr, 32, prim);

	/**
	 * ���豸û��ʹ��ʱ�����ϵĹ㲥��ַ�������ַ������ʹ�ã�����ڴ˿����˳���
	 * ���豸ʹ�ܺ���������ǵĹ㲥��ַ�������ַ��
	 */
	if (!(dev->flags&IFF_UP))
		return;

	/* Add broadcast address, if it is explicitly assigned. */
	/**
	 * �����ȷ�����˹㲥��ַ��Ϊ���޹㲥��ַ255.255.255.255����ô����ӵ��ù㲥��ַ��·�ɣ���Ϊ·�ɲ��ҳ���Ҫ���ȫ255�Ĺ㲥��ַ
	 */
	if (ifa->ifa_broadcast && ifa->ifa_broadcast != 0xFFFFFFFF)
		/**
		 * ��������豸�㲥��ַ��·�ɱ��С�
		 */
		fib_magic(RTM_NEWROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);

	if (!ZERONET(prefix) && !(ifa->ifa_flags&IFA_F_SECONDARY) && /* �ڶ�IP��ַ����Ҫ�������ַ��·�ɣ�Ҳ����Ҫ�������Ĺ㲥��ַ��·�ɣ���ص�����ַ����ʱ�Ѿ��������Щ·��� */
	    (prefix != addr || ifa->ifa_prefixlen < 32)) {/* ��prefixlenΪ32ʱ����������ֻ��һ����Ч��ַ�����Բ���Ҫ�����Ĺ㲥·�ɻ�����·�ɡ� */
		/**
		 * ��prefixlenΪ31ʱ��ֻ��һ������λ���룬������������ֻ��������ַ��
		 * clear����λ�ĵ�ַ��ʾ�����ַ��set����λ�ĵ�ַ��ʾ������ַ�������������õĵ�ַ����
		 * �����������Ҫ����������ַ��·�ɣ�������Ҫ�������Ĺ㲥��ַ��·�ɡ�
		 */
		fib_magic(RTM_NEWROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, prefix, ifa->ifa_prefixlen, prim);

		/* Add network specific broadcasts, when it takes a sense */

		/**
		 * ��prefixlenС��31ʱ�������ڰ����ĵ�ַ�����ڻ�����ĸ������ڱ��ص�ַ�������ַ�͹㲥��ַֻռ��������������������ڻ����԰���������ַ��
		 * ��ʱ�ں����һ���������Ĺ㲥��ַ��·�ɼ�һ�������������ε�ַ��·�ɡ�
		 */
		if (ifa->ifa_prefixlen < 31) {
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix, 32, prim);
			fib_magic(RTM_NEWROUTE, RTN_BROADCAST, prefix|~mask, 32, prim);
		}
	}
}

/**
 * ����һ���ӿ�ɾ��һ��IP��ַʱ��·����ϵͳ�õ�֪ͨ�Ա�����·�ɱ��·�ɻ��档����ͨ��fib_del_ifaddr��ʵ�ֵġ�
 */
static void fib_del_ifaddr(struct in_ifaddr *ifa)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct net_device *dev = in_dev->dev;
	struct in_ifaddr *ifa1;
	struct in_ifaddr *prim = ifa;
	u32 brd = ifa->ifa_address|~ifa->ifa_mask;
	u32 any = ifa->ifa_address&ifa->ifa_mask;
#define LOCAL_OK	1
#define BRD_OK		2
#define BRD0_OK		4
#define BRD1_OK		8
	unsigned ok = 0;

	if (!(ifa->ifa_flags&IFA_F_SECONDARY))
		/**
		 * ɾ�����ص�ַ��
		 */
		fib_magic(RTM_DELROUTE, dev->flags&IFF_LOOPBACK ? RTN_LOCAL :
			  RTN_UNICAST, any, ifa->ifa_prefixlen, prim);
	else {
		/**
		 * ����ɾ��һ���ڶ�IP��ַ����ô������һ����IP��ַ������ͬһ���Ρ�
		 * ������ǣ���ǰ��ĳ���ط����ܳ����������һ������
		 */
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (prim == NULL) {
			printk(KERN_DEBUG "fib_del_ifaddr: bug: prim == NULL\n");
			return;
		}
	}

	/* Deletion is more complicated than add.
	   We should take care of not to delete too much :-)

	   Scan address list to be sure that addresses are really gone.
	 */
	/**
	 * fib_del_ifaddrɨ���豸�����õ����е�ַ�������Щ��Ҫɾ����
	 */
	for (ifa1 = in_dev->ifa_list; ifa1; ifa1 = ifa1->ifa_next) {
		if (ifa->ifa_local == ifa1->ifa_local)
			ok |= LOCAL_OK;
		if (ifa->ifa_broadcast == ifa1->ifa_broadcast)
			ok |= BRD_OK;
		if (brd == ifa1->ifa_broadcast)
			ok |= BRD1_OK;
		if (any == ifa1->ifa_broadcast)
			ok |= BRD0_OK;
	}

	if (!(ok&BRD_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);
	if (!(ok&BRD1_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, brd, 32, prim);
	if (!(ok&BRD0_OK))
		fib_magic(RTM_DELROUTE, RTN_BROADCAST, any, 32, prim);
	if (!(ok&LOCAL_OK)) {
		fib_magic(RTM_DELROUTE, RTN_LOCAL, ifa->ifa_local, 32, prim);

		/* Check, that this local address finally disappeared. */
		/**
		 * ��������£���ɾ��һ���ڶ�IP��ַʱ��·����ϵͳֻ��Ҫɾ������IP��ַ��·�ɣ�����ɾ�������ε�ַ�͹㲥��ַ��·�ɣ���Ϊ��IP��ַ���Լ��������ܴ��ڵĵڶ�IP��ַ����Ȼ��Ҫ���ǡ�
		 * ����������ɾ��һ���ڶ�IP��ַʱ������Ҫɾ������IP��ַ��·�ɣ����磬������Ա���õ�һ��IP��ַ����������ͬ���������롣
		 */
		if (inet_addr_type(ifa->ifa_local) != RTN_LOCAL) {
			/* And the last, but not the least thing.
			   We must flush stray FIB entries.

			   First of all, we scan fib_info list searching
			   for stray nexthop entries, then ignite fib_flush.
			*/
			/**
			 * ����·�ɱ�
			 */
			if (fib_sync_down(ifa->ifa_local, NULL, 0))
				fib_flush();
		}
	}
#undef LOCAL_OK
#undef BRD_OK
#undef BRD0_OK
#undef BRD1_OK
}

/**
 * ͨ������fib_sync_down����ֹ�������dev�ϵ�IPЭ�顣
 * ��ɾ����·��������Ϊ��ֵʱ��ͨ��fib_sync_down�ķ���ֵ�жϣ����ú���Ҳ����flush·�ɱ�
 */
static void fib_disable_ip(struct net_device *dev, int force)
{
	if (fib_sync_down(0, dev, force))
		fib_flush();
	rt_cache_flush(0);
	arp_ifdown(dev);
}

/**
 * ���豸��IP���÷����仯��·����ϵͳ���յ�һ��֪ͨ������fib_inetaddr_event��������¼���
 */
static int fib_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr*)ptr;

	switch (event) {
	case NETDEV_UP:
		/**
		 * �����豸���Ѿ�������һ���µ�IP��ַ��
		 * �����ӱ��뽫��Ҫ��·������ӵ�local_table·�ɱ��У�������fib_add_ifaddr��������ɵġ�
		 */
		fib_add_ifaddr(ifa);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(ifa->ifa_dev->dev);
#endif
		rt_cache_flush(-1);
		break;
	case NETDEV_DOWN:
		/**
		 * �����豸���Ѿ�ɾ����һ��IP��ַ��
		 * �����ӱ��뽫��ǰ��NETDEV_UP�¼���ӵ�·����ɾ����������fib_del_ifaddr����ɵġ�
		 */
		fib_del_ifaddr(ifa);
		/**
		 * ��fib_del_ifaddr��һ���豸��ɾ�����һ��IP��ַʱ��fib_inetaddr_event��������fib_disable_ip����ֹ���豸�ϵ�IPЭ�顣
		 */
		if (ifa->ifa_dev && ifa->ifa_dev->ifa_list == NULL) {
			/* Last address was deleted from this interface.
			   Disable IP.
			 */
			fib_disable_ip(ifa->ifa_dev->dev, 1);
		} else {
			rt_cache_flush(-1);
		}
		break;
	}
	return NOTIFY_DONE;
}

/**
 * ��һ���豸��״̬����ĳЩ���ò��ַ����仯��·����ϵͳ���յ�֪ͨ������fib_netdev_event��������¼���
 */
static int fib_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev = __in_dev_get(dev);

	if (event == NETDEV_UNREGISTER) {
		/**
		 * ��һ���豸ע��ʱ����·�ɱ�����·�ɻ��棩ɾ��ʹ�ø��豸������·���
		 * �����·��·�������һ����������һ��ʹ�ø��豸�����·����Ҳ��ɾ����
		 */
		fib_disable_ip(dev, 2);
		return NOTIFY_DONE;
	}

	if (!in_dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		/**
		 * ��һ���豸��ΪUPʱ�����뽫����豸������IP��ַ��ص�·�ɱ�����ӵ�ip_fib_local_table·�ɱ��С�
		 * ����ͨ���Ը��豸�����õ�ÿһ��IP��ַ��������fib_add_ifaddr��������ɵġ�
		 */
		for_ifa(in_dev) {
			fib_add_ifaddr(ifa);
		} endfor_ifa(in_dev);
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		fib_sync_up(dev);
#endif
		rt_cache_flush(-1);
		break;
	case NETDEV_DOWN:
		/**
		 * ��һ���豸��ΪDOWNʱ������fib_disable_ip��·�ɱ�����·�ɻ��棩ɾ��ʹ�ø��豸������·���
		 */
		fib_disable_ip(dev, 0);
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGE:
		/**
		 * ��һ���豸�����÷����仯ʱ��flush·�ɱ��档
		 * ��������ñ仯��MTU��PROMISCUITY״̬���޸ġ�
		 */
		rt_cache_flush(0);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block fib_inetaddr_notifier = {
	.notifier_call =fib_inetaddr_event,
};

static struct notifier_block fib_netdev_notifier = {
	.notifier_call =fib_netdev_event,
};

void __init ip_fib_init(void)
{
#ifndef CONFIG_IP_MULTIPLE_TABLES
	ip_fib_local_table = fib_hash_init(RT_TABLE_LOCAL);
	ip_fib_main_table  = fib_hash_init(RT_TABLE_MAIN);
#else
	fib_rules_init();
#endif

	register_netdevice_notifier(&fib_netdev_notifier);
	register_inetaddr_notifier(&fib_inetaddr_notifier);
}

EXPORT_SYMBOL(inet_addr_type);
EXPORT_SYMBOL(ip_dev_find);
EXPORT_SYMBOL(ip_rt_ioctl);
