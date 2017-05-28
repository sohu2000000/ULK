/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Version:	$Id: ip_output.c,v 1.100 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when 
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path 
 *					for decreased register pressure on x86 
 *					and more readibility. 
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/checksum.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

/**
 * �ñ������ڴ��������ǣ��������貦�Žӿڵĵ�ַ���׽���û���յ��κλظ���ֱ���ýӿڴ�Ϊֹ�����ip_dynaddr���趨���׽��־ͻ��������Ű󶨡�
 */
int sysctl_ip_dynaddr;
/**
 * ����IP TTL�ֶε�Ĭ��ֵ�����ڵ������������ಥ������Ĭ��ֵ��1������û����Ӧ��sysctl�����ɹ��趨��
 */
int sysctl_ip_default_ttl = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
/**
 * ����IP��������У��͡�
 * ���Ƕ�ip_fast_csum��һ���򵥰�װ���ڵ���ip_fast_csumǰ��Ԥ�Ƚ�iphdr->check����Ϊ0.
 */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	newskb->mac.raw = newskb->data;
	__skb_pull(newskb, newskb->nh.raw - newskb->data);
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	BUG_TRAP(newskb->dst);

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_loopback_xmit(newskb);
#endif
	netif_rx(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/* 
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  u32 saddr, u32 daddr, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)skb->dst;
	struct iphdr *iph;

	/* Build the IP header. */
	if (opt)
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr) + opt->optlen);
	else
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr));

	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	iph->tot_len  = htons(skb->len);
	ip_select_ident(iph, &rt->u.dst, sk);
	skb->nh.iph   = iph;

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}
	ip_send_check(iph);

	skb->priority = sk->sk_priority;

	/* Send it out. */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);
}

/**
 * L3����L2��Ľӿڡ�
 */
static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct hh_cache *hh = dst->hh;
	struct net_device *dev = dst->dev;
	int hh_len = LL_RESERVED_SPACE(dev);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->hard_header)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_finish_output2(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	/**
	 * �л����֡ͷ��
	 */
	if (hh) {
		int hh_alen;

		read_lock_bh(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(hh->hh_len);
		/**
		 * ����������skb�������С�
		 */
  		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		read_unlock_bh(&hh->hh_lock);
	        skb_push(skb, hh->hh_len);
		return hh->hh_output(skb);
	} else if (dst->neighbour)/* �����L2֡ͷ����Ч�� */
		return dst->neighbour->output(skb);/* ����neigh->output����������ܽ����ŵ�����������Ӻ��͡� */

	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

int ip_finish_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
		       ip_finish_output2);
}

int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
					newskb->dev, 
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (skb->nh.iph->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
				newskb->dev, ip_dev_loopback_xmit);
	}

	if (skb->len > dst_pmtu(&rt->u.dst))
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

int ip_output(struct sk_buff *skb)
{
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	if (skb->len > dst_pmtu(skb->dst) && !skb_shinfo(skb)->tso_size)
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

/**
 * TCP��SCTP���Ͱ����õĺ�����
 * �˺���ֻ��������������������д��������Ҫ����Ϣ������ͨ��skbֱ�ӻ��߼�ӵĴ�ȡ��
 *		Skb��		Ҫ����İ��Ļ������������������ݽṹ������IP��ͷ�Լ����������Ҫ�����в���������һ�����أ�����ס��ip_queue_xmit���ڴ����ز����İ���ת����û����ص��׽��֡�
 *		Ipfragok��	��Ҫ��SCTPʹ�õı�־������ָ���Ƿ�����ֶΡ�
 */
int ip_queue_xmit(struct sk_buff *skb, int ipfragok)
{
	/**
	 * ��skb��ص��׽��ְ�����һ����Ϊopt��ָ�룬ָ��IPѡ��ṹ��
	 * �˽ṹ����IP��ͷ�е�ѡ�����洢��ʽʹ��IP��ĺ��������ڴ�ȡ��
	 * �˽ṹ�Ƿ���socket�ṹ�еģ���Ϊ�˽ṹ��ÿ��Ҫͨ�����׽��ִ���İ����Զ�����ͬ�ġ�
	 * Ϊÿ�����ؽ�����Ϣ̫�˷��ˡ�
	 */
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	/**
	 * opt�ṹ����һЩ�ֶ���ƫ������ָ�����������ڱ�ͷ�е���Щλ�ô洢IPѡ�������ʱ�����IP��ַ��
	 */
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	/**
	 * ����������ѱ��趨��ȷ·����Ϣ��skb->dst������û�б�Ҫ��ѯ·�ɱ�
	 * ����������SCTPЭ�鴦��ʱ����ĳЩ����������п��ܵ�
	 */
	rt = (struct rtable *) skb->dst;
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	/**
	 * ����������£�ip_queue_xmit�����׽��ֽṹ���Ƿ��ѻ�����һ��·����
	 * ����еĻ����ͻ�ȷ����·���Ƿ���Ȼ��Ч����__sk_dst_check��飩
	 */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	/**
	 * �׽��ֻ�û��һ�������·�����ã��������IP��һֱ���õ�·���ڴ�ʱʧЧ�ˣ�����·��Э������ˣ�
	 */
	if (rt == NULL) {
		u32 daddr;

		/* Use correct destination address if we have options. */
		/**
		 * daddr�ǳ���ʹ�õ�·�ɵ�ַ�������Դ·�ɣ���ʹ��IPѡ�����趨�ĵ�ַ��
		 */
		daddr = inet->daddr;
		if(opt && opt->srr)
			daddr = opt->faddr;

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .uli_u = { .ports =
						       { .sport = inet->sport,
							 .dport = inet->dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			/**
			 * ����ip_route_output_slow�ҵ�һ����·����Ȼ�󽫽���洢��sk���ݽṹ��
			 */
			if (ip_route_output_flow(&rt, &fl, sk, 0))
				goto no_route;
		}
		/**
		 * ����ѯ����·�ɻ��浽sock�ṹ�С�
		 */
		__sk_dst_set(sk, &rt->u.dst);
		/**
		 * tcp_v4_setup_caps��ѳ��豸��һЩ���ܴ洢���׽���sk��
		 */
		tcp_v4_setup_caps(sk, &rt->u.dst);
	}
	/**
	 * ����·�ɻ���������ü�����
	 */
	skb->dst = dst_clone(&rt->u.dst);

packet_routed:
	/**
	 * ������ϸ�Դ·�ɣ�����·�ɱ������ĳ��豸����һ�������ϣ����˳���
	 */
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	/**
	 * ��ip_queue_xmit����skbʱ��skb->data��ָ��L3��Ч���أ�L4Э���ڴ�д�������ݣ��Ŀ��ˡ�
	 * L3��ͷ���ڴ�ָ��֮ǰ�����ԣ������ʹ��skb->push��skb->data�����ƶ���ʹ��ָ��L3��IP��ͷ�Ŀ��ˡ�
	 */
	iph = (struct iphdr *) skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	/**
	 * ��IP��ͷ�е�һ���ֶ�����ʼ����
	 * �����趨�����ֶε�ֵ��veriosn��ihl��tos������Ϊ���ǹ���ͬһ��16λ��
	 * ��ˣ���һ���ѱ�ͷ�еİ汾����Ϊ4���ѱ�ͷ��������Ϊ5������TOS���ó�inet->tos��
	 */
	*((__u16 *)iph)	= htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	iph->tot_len = htons(skb->len);
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;
	skb->nh.iph   = iph;
	/* Transport layer set skb->h.foo itself. */

	/**
	 * ���IP��ͷ�а�����һЩѡ��˺����������"��ͷ����"�ֶ�iph->length�����Ѿ���Ԥ������Ϊ��ʼֵ5����Ȼ�����ip_options_ build������Щѡ�
	 * Ip_options_build��ʹ��opt���������Ѿ���Ԥ�ȳ�ʼ��Ϊinet->opt���������ѡ���ֶΣ���ʱ����������IP��ͷ��ע�⣬ip_options_build�����һ������������Ϊ0����ָ���ñ�ͷ������Ƭ�Ρ�
	 */
	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->daddr, rt, 0);
	}

	/**
	 * ip_select_ident_more����ݸð��Ƿ���ܱ��ֶζ��ڱ�ͷ���趨IP ID
	 */
	ip_select_ident_more(iph, &rt->u.dst, sk, skb_shinfo(skb)->tso_segs);

	/* Add an IP checksum. */
	/**
	 * ip_send_check���IP��ͷ����У��͡�
	 */
	ip_send_check(iph);

	/**
	 * ��������ʹ��skb->priority������Ҫ�Ѱ�������һ�������С�
	 * ����һ�������ھ����ð����챻���ݡ��˺����е�ֵ������sock�ṹ�ġ�
	 * ����ip_forward��������Ǳ������������û�б����׽��֣�����ֵ�Ǹ���IP TOS��ֵ����һ��ת�����Ƶ����á�
	 */
	skb->priority = sk->sk_priority;

	/**
	 * ����Netfilter���˽�ð��Ƿ���Ȩ�����������裨dst_output���������Լ������䡣
	 */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);

no_route:
	IP_INC_STATS(IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	to->security = from->security;
	dst_release(to->dst);
	to->dst = dst_clone(from->dst);
	to->dev = from->dev;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
#ifdef CONFIG_NETFILTER
	to->nfmark = from->nfmark;
	to->nfcache = from->nfcache;
	/* Connection association is same as pre-frag packet */
	nf_conntrack_put(to->nfct);
	to->nfct = from->nfct;
	nf_conntrack_get(to->nfct);
	to->nfctinfo = from->nfctinfo;
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(to->nf_bridge);
	to->nf_bridge = from->nf_bridge;
	nf_bridge_get(to->nf_bridge);
#endif
#ifdef CONFIG_NETFILTER_DEBUG
	to->nf_debug = from->nf_debug;
#endif
#endif
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */
/**
 * �����Ƭ��
 *		skb:		����Ҫ���ֶε�IP���Ļ��������˰�������һ���Ѿ���ʼ����IP��ͷ�������IP��ͷ���ᱻ���������ڿ���������Ƭ���ڡ�
 *		output��	���ڴ���Ƭ�εĺ�����
 */
int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	int not_last_frag;
	struct rtable *rt = (struct rtable*)skb->dst;
	int err = 0;

	/**
	 * ��·����ȡ�����豸��
	 */
	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = skb->nh.iph;

	/**
	 * ��������IP����Ϊ��Դ������DF��־���޷����ֶΣ���ip_fragment�ᴫ��һ��ICMP������Դ�ظ�֪�����⡣Ȼ�����ð���
	 */
	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(dst_pmtu(&rt->u.dst)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	/**
	 * ����MTU���������㱨ͷ��
	 */
	mtu = dst_pmtu(&rt->u.dst) - hlen;	/* Size of data space */

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	/**
	 * �Ѿ��ֶ��ˣ��˴����п��ٷֶΡ�
	 * �����ת���İ����򲻻���frag_list����ô��Ҫ�����ٷ�Ƭ���̡�
	 */
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;
		int first_len = skb_pagelen(skb);

		/**
		 * �ڳ��Խ��п��ٷ�Ƭǰ���Ƚ���һЩ��飬ȷ���ܹ����п��ٷ�Ƭ��
		 */
		if (first_len - hlen > mtu ||	/* ��һ���εĳ��ȣ���ҳ���еĳ��ȣ����ܳ���MTU */
		    ((first_len - hlen) & 7) || /* ��һ���εĳ���û��8�ֽڶ��� */
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||/* ԭʼ������һ�����ĵ�Ƭ�Ρ� */
		    skb_cloned(skb))/* Ƭ�α������������Ͳ��ܶ�Ƭ�ν����޸�(���¼���У���) */
			goto slow_path;

		/**
		 * ��fraglist�е����ݽ����ж�
		 */
		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next) {
			/* Correct geometry. */
			if (frag->len > mtu ||	/* ����Ƭ�γ��Ȳ��ܳ���MTU */
			    ((frag->len & 7) && frag->next) || /* �������һ��Ƭ�Σ����ҳ��Ȳ���8�ֽڶ��� */
			    skb_headroom(frag) < hlen)/* Ƭ�γ��Ȳ�������L2��ͷ */
			    goto slow_path;

			/* Partially cloned skb? */
			if (skb_shared(frag))/* �ֶα����� */
				goto slow_path;
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		/**
		 * ��һ��Ƭ�ε�IP��ͷ��ʼ����ѭ������ɣ���Ϊ���Զ�������Ż���
		 */
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		/**
		 * ����ֱ������MF��־��offsetΪĬ��ֵ0.
		 */
		iph->frag_off |= htons(IP_MF);
		ip_send_check(iph);

		/**
		 * ѭ������ÿ��Ƭ�Ρ�
		 */
		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				frag->h.raw = frag->data;
				frag->nh.raw = __skb_push(frag, hlen);
				/**
				 * �ӵ�һ��IPƬ���аѱ�ͷ���Ƶ���ǰƬ�Ρ�
				 */
				memcpy(frag->nh.raw, iph, hlen);
				iph = frag->nh.iph;
				iph->tot_len = htons(frag->len);
				/**
				 * �ӵ�һ��Ƭ���аѹ���������Ƶ���Ƭ���С�
				 */
				ip_copy_metadata(frag, skb);
				/**
				 * ��һ��Ƭ�δ��������Ҫ����ip_options_fragment�޸ı�ͷ��
				 * ����������Ƭ�εı�ͷ�ͼ򵥵ö��ˡ�
				 */
				if (offset == 0)
					ip_options_fragment(frag);
				/**
				 * ���㱨ͷ��ƫ������
				 */
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				/**
				 * ����������һ��Ƭ�Σ�������MF��־��
				 */
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				/**
				 * ��ͷ��У�����Ҫ���¼��㡣
				 */
				ip_send_check(iph);
			}
			/**
			 * ����Ƭ�Ρ���IPV4��˵���ص��ĺ�����ip_finish_output��
			 */
			err = output(skb);

			/**
			 * �������󡣻��ߴ���������Ƭ���ˡ�
			 */
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		/**
		 * û�з������󡣷��ء�
		 */
		if (err == 0) {
			IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		/**
		 * ��������������ͷ�ʣ�������Ƭ�Ρ�
		 */
		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
		return err;
	}

/**
 * ���ٷֶΡ�
 */
slow_path:
	/**
	 * ��Ҫ���з�Ƭ�����ݳ��ȣ�����L2��ͷ����ֵ�Ǳ��ĳ��ȡ�
	 */
	left = skb->len - hlen;		/* Space per frame */
	/**
	 * Ptr����Ҫ���ֶεİ����ƫ����������ֵ�����ŷֶι����Ľ��ж��ƶ���
	 */
	ptr = raw + hlen;		/* Where to start from */

	/**
	 * ������·�㱣���ռ�
	 */
#ifdef CONFIG_BRIDGE_NETFILTER
	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header */
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, nf_bridge_pad(skb));
	mtu -= nf_bridge_pad(skb);
#else
	ll_rs = LL_RESERVED_SPACE(rt->u.dst.dev);
#endif
	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	/**
	 * not_last_frag��ʶ�ǲ������һ����Ƭ��
	 */
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	/**
	 * Ϊÿ����Ƭ����һ���»�����skb2��
	 */
	while(left > 0)	{
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		/**
		 * ÿ��Ƭ�εĳ��ȣ����ΪPMTU��
		 */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		/**
		 * RFCǿ��Ҫ��ÿ��Ƭ��8�ֽڶ��롣
		 */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */
		/**
		 * ����һ��Ƭ�εĻ������ߴ������и���֮�ͣ�
 		 *		IP��Ч���صĳߴ硣
 		 *		IP��ͷ�ĳߴ硣
 		 *		L2��ͷ�ĳߴ硣
		 */
		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(printk(KERN_INFO "IP: frag: no memory for new fragment!\n"));
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */
		/**
		 * ��skb�и���һЩ�ֶε�skb2�У�����һЩ�ֶ���ip_copy_metadata����
		 */
		ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb2->nh.raw = skb2->data;
		skb2->h.raw = skb2->data + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		/**
		 * �����»�����������socket��
		 */
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */
		/**
		 * ���ڣ���ʼ����ʵ����д�뻺�����С�
		 * ���ȸ���IP��ͷ��
		 */
		memcpy(skb2->nh.raw, skb->data, hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		/**
		 * ��ԭ�а��е���Ч���ظ��Ƶ��°��С������޷�ʹ��memcpy��
		 * ��Ϊ�����ڵ����ݿ��ܷ�ɢ��Ƭ��������ڴ�ҳ���У�����������data�С�
		 * ��L4��ֶκ󣬿������ڽ��������ߵ����ٷֶ����̡�
		 */
		if (skb_copy_bits(skb, ptr, skb2->h.raw, len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = skb2->nh.iph;
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		/**
		 * �Ե�һ��Ƭ��(offset == 0)��˵������IPͷ������ԭ��������ѡ�
		 * ����������һ��Ƭ�ε�IPͷ����Ҫ����ip_options_fragment�����ԭ��IP����ص�ip_opt�ṹ�����ݡ�
		 * �������Ժ��Ƭ�ξͲ����в���Ҫ��ѡ�
		 */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		/**
		 * left > 0��ʾ��������Ƭ�β������һ��Ƭ�Ρ�
		 * not_last_frag��ʾ����Ƭ�İ���������һ��Ƭ�β��Ҳ������һ��Ƭ�Ρ�
		 * ����������£�����Ҫ����MF��־��
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		/**
		 * ptr����ǰ���ڷֶεİ��ڵ�ƫ������offset����ǰƬ����ԭ���ڵ�ƫ������
		 * һ�������������ֵ����ȵģ����ǣ���Ҫoffset��ԭ���ǣ����ֶεİ�����������һ�����ķ�Ƭ����ʱ��offsetӦ�ô��ڵ���ptr��
		 */
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */

		IP_INC_STATS(IPSTATS_MIB_FRAGCREATES);

		/**
		 * ���±�ͷ���ȣ�������ΪҪ����ѡ��ĳߴ硣
		 */
		iph->tot_len = htons(len + hlen);
		/**
		 * ����У��͡�
		 */
		ip_send_check(iph);
		/**
		 * ʹ��output������Ƭ�Σ���IPV4��˵�����������ip_finish_output��
		 */
		err = output(skb2);
		if (err)
			goto fail;
	}
	kfree_skb(skb);
	IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb); 
	IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
	return err;
}

/**
 * ��Ӧ�ó����UDP��Raw IP�׽��ַ���һ��sendmsgϵͳ����ʱ���ں����ջ����ip_append_data����ip_generic_getfrag����getfrag������
 * ��������£��Ѿ�֪����������ʼ���������û��ռ䡣
 */
int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_HW) {/* ����Ҫ����У��� */
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		unsigned int csum = 0;
		/**
		 * �ڴ��û�̬��������ʱ��ͬʱ����У��͡�
		 */
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline unsigned int
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	unsigned int csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *	
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
/**
 * ĳЩL4Э��(��UDP)�����ݴ����ݣ�ֱ���ﵽIP�����󳤶�(64K).
 * ip_append_data�����������������
 * 		sk:			�ð��������׽��֡������ݽṹ����һЩ��������IPѡ����Ժ����������дIP��ͷ��ͨ��ip_push_pending_frames��������
 *		from��		ָ��L4�������Ŵ�������ݣ���Ч���أ�ָ�롣�ⲻ���ں�ָ�룬�����û��ռ��ָ�룬getfrag�����Ĺ���������ȷ������һָ�롣
 *		getfrag��	���ڰѽ�����L4�����Ч���ؿ���������������һЩ����Ƭ���С�
 *		length��	Ҫ�����������������L4��ͷ��L4��Ч���أ���
 *		transhdrlen�����䣨L4����ͷ�ĳߴ硣���䱨ͷ�ķ���������Щ������TCP��UDP�Լ�ICMPЭ��ı�ͷ��
 * 		ipc��		��ȷת��������Ҫ����Ϣ
 *		rt��		��˰���ص�·�ɱ�����Ŀ����ip_queue_xmit���մ���Ϣʱ��ip_append_data������������ͨ��ip_route_output_flow���ռ�����Ϣ��
 *		flags��		�˱����ɰ����κ�һ��MSG_XXX��־��������include/linux.socket.h�У����˺������õ�����������־��
 *			MSG_MORE��		�˱�־��Ӧ�ó���ʹ�ã�����֪L4�����Ͼ��и����������䡣�������������˱�־�ᴫ����L3�㡣�Ժ����Ǿͻῴ�����ڷ��仺����ʱ������Ϣ�к��ô���
 *			MSG_DONTWAIT��	���˱�־�趨ʱ����ip_append_data�ĵ���һ�������ܵ�������Ip_append_data���ܱ���Ϊ�׽���sk����һ��������������sock_alloc_send_skb������sock_alloc_send_skb�õ�������ʱ�����Ƕ���ס��ͨ����ʱ������������ʱ������ǰ������Щ�ռ���ã���Ȼ����ʧ�ܡ��˱�־������ǰ����ѡ������ѡ��
 *			MSG_PROBE��		���˱�־�趨ʱ���û���ʵ���봫���κζ�������ֻ����̽��·�������磬�˱�־�����ڲ���ͨ��ָ��IP��ַ��·���ϵ�PMTU���ɲο�net/ipv4/raw.c�е�raw_sed_hdrinc������˱�־�����ã�ip_append_dataֻ�����̴���һ������ɹ��ķ��ش��롣
 */
int ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable *rt,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	/**
	 * Ҫ����IP��ͷ��IPѡ����˱���ΪNULLʱ����û��ѡ�
	 */
	struct ip_options *opt = NULL;
	int hh_len;
	/**
	 * �ⲿ��ͷ��exthdrlen����rt���ȡ�õġ�
	 * �ⲿ��ͷ�ķ�������Щ��ipsec�׼����Э����ʹ�õı�ͷ�����������ͷ��AH���Լ���װ��ȫ��Ч���ر�ͷ��ESP����
	 */
	int exthdrlen;
	/**
	 * ��rt��ص�PMTU��
	 */
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen;
	int csummode = CHECKSUM_NONE;

	if (flags&MSG_PROBE)
		return 0;

	/**
	 * �ǽ����ĵ�һ�����������Ҫ��ʼ����cork�����ģ�inet�ṹ�ڵ����ݡ�
	 */
	if (skb_queue_empty(&sk->sk_write_queue)) {
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		/**
		 * ��Ҫ����ѡ���������󱣴浽cork�С�
		 */
		if (opt) {
			if (inet->cork.opt == NULL) {
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);
			inet->cork.flags |= IPCORK_OPT;
			inet->cork.addr = ipc->addr;
		}
		dst_hold(&rt->u.dst);
		/**
		 * �õ�·���ϵ�PMTU�������仺��������
		 */
		inet->cork.fragsize = mtu = dst_pmtu(&rt->u.dst);
		inet->cork.rt = rt;
		inet->cork.length = 0;
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;
		if ((exthdrlen = rt->u.dst.header_len) != 0) {
			length += exthdrlen;
			transhdrlen += exthdrlen;
		}
	} else {
		rt = inet->cork.rt;
		/**
		 * cork�а���opt��
		 */
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

		/**
		 * ֻ�е�һ����������Ҫ���䱨ͷ����ˣ�����Ļ�������Ҫ��������Ϊ0.
		 */
		transhdrlen = 0;
		exthdrlen = 0;
		/**
		 * ȡ�������PMTU.
		 */
		mtu = inet->cork.fragsize;
	}
	/**
	 * hh_len��L2��ͷ�ĳ��ȡ���ΪIP֮ǰ�����б�ͷ�ڻ������б����ռ�ʱ��ip_append_data����֪��L2��ͷ��Ҫ���ٿռ䡣
	 * ���һ�������豸����������䱨ͷ����ʼ��ʱ���Ͳ���Ҫ���·���ռ䣬�����ƶ��������ڵ��������ڳ��ռ��L2��ͷ�ˡ�
	 */
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);

	/**
	 * Fraghdrlen��IP��ͷ������IPѡ��ĳߴ�
	 */
	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	/**
	 * maxfraglen��IPƬ�ε����ߴ磨����·��PMTU����
	 */
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	/**
	 * IP������ͷ����Ч���أ������ߴ���64KB��
	 * ��һ�㲻�������ڸ���Ƭ�Σ�Ҳ����������������ЩƬ�����ջ�����ɴ˰�����
	 * ���ǣ�ip_append_data���¼Ϊ�ض��������յ��������ݣ����ܾ�����64KB�����ơ�
	 */
	if (inet->cork.length + length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	/**
	 * �����ʼ���ľֲ�����csummode�ᱻָ�ɸ���һ��������skb->ip_summed��
	 * �����Ҫ�ֶΣ�����ip_append_data�ݴ˷������Ļ�������ÿ��IPƬ��һ�������������������������skb->ip_summed�ͻᱻ���CHECKSUM_NONE��
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features&(NETIF_F_IP_CSUM|NETIF_F_NO_CSUM|NETIF_F_HW_CSUM) &&
	    !exthdrlen)
		csummode = CHECKSUM_HW;

	/**
	 * ��¼���л��������ܳ���
	 */
	inet->cork.length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		/**
		 * �Ե�һ����������˵������Ҫ����MSG_MORE��־��NETIF_F_SG��־��������Ҫ����sk_buff�ġ�
		 */
		goto alloc_new_skb;

	/**
	 * �����length��ֵ�������ip_append_data�ĵ������봫�����������
	 * Ȼ����һ������ѭ������ֵ�ʹ���ʣ��Ҫ�������������
	 */
	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		/**
		 * copy�Ǳ�����Ҫ������������
		 * ���ȼ����һ���������Ƿ񻹿��Է�һЩ���ݽ�ȥ��
		 */
		copy = mtu - skb->len;
		/**
		 * ������ȫ����ʣ��İ�����Ҫ����copyֵ����Ϊÿ����Ƭ��Ҫ8�ֽڶ��롣��mtu������8�ֽڶ���ġ�
		 */
		if (copy < length)
			/**
			 * ���ݷ�Ƭ��С���¼�����Էŵ���һ����������������
			 */
			copy = maxfraglen - skb->len;
		/**
		 * ��һ����Ƭ���ܴ���κ������ˣ���Ҫ�ٷ���һ����������
		 */
		if (copy <= 0) {
			char *data;
			/**
			 * datalen��Ҫ����������������Ļ���������������
			 * ��ֵ�������������Ԥ�ȳ�ʼ����ʣ����������length����һ��Ƭ���������ɵ������������fraghdrlen�����Լ�һ�����п��ޣ�������ǰһ���������ļ�϶��fraggap����
			 */
			unsigned int datalen;
			unsigned int fraglen;
			/**
			 * �������һ�����������������һ��IPƬ�Σ����⣬����Ƭ�ζ�������ѭһ��ԭ��IPƬ�ε���Ч���ر�����8�ֽڵı�����
			 * ��ˣ����ں˷����һ���»��������Ǹ����Ƭ��ʹ��ʱ�����ܱ����ǰһ����������β���ƶ�һ�����ݣ���ߴ�Ϊ0��7�ֽڣ����·��仺������ͷ����
			 * ���仰˵�������������������㣬��fraggapΪ0��
			 *	 	PMTU����8�ֽڵı�����
 			 *		��ǰIPƬ�εĳߴ绹����PMTU��
 			 *		��ǰIPƬ�εĳߴ��Ѿ�����8�ֽڵı�����
			 */
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			/**
			 * ������Ҫ��ǰһ��Ƭ�����ƶ��������ݵ��»�������
			 */
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;
			/**
			 * �»�������������ʣ������ݡ����»�������Ҫ����8�ֽڶ��롣
			 */
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
			/**
			 * ��Ƭ�ܳ���
			 */
			fraglen = datalen + fragheaderlen;

			/**
			 * ���Ԥ�ڻ��и������ݣ���������豸�޷������ɢ/�ۼ�IO���˻������ͻ������ߴ罨��������PMTU����
			 */
			if ((flags & MSG_MORE) && 
			    !(rt->u.dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else/* ���򻺳����Ĵ�СֻҪ�ܹ����ɵ�ǰ���ݾ����ˡ� */
				alloclen = datalen + fragheaderlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			/**
			 * ��ip_append_data��������Ƭ��ʱ���ͱ��뿼��һЩ��β����IPSec�ı�β���Ƿ���ڡ�
			 * �����Ȼ��һ��BUG�����Ժ�İ汾�Ѿ��޸������ˡ�������ж�����Ӧ����:if (datalen == length + fraggap)
			 */
			if (datalen == length)
				alloclen += rt->u.dst.trailer_len;

			if (transhdrlen) {
				/**
				 * sock_alloc_send_skbΪ��һ����Ƭ�����ڴ档
				 */
				skb = sock_alloc_send_skb(sk, 
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				/**
				 * sock_wmallocΪ������Ƭ�����ڴ档
				 */
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk, 
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
			}
			/**
			 * ���ܷ����ڴ��ˡ�
			 */
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen);
			skb->nh.raw = data + exthdrlen;
			data += fragheaderlen;
			skb->h.raw = data + exthdrlen;

			/**
			 * ��Ҫ��ǰһ���������и��Ƽ����ֽڵ��»�������
			 */
			if (fraggap) {
				/**
				 * ��ǰһ�����������Ƽ����ֽڣ����ض�ǰһ����������
				 */
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				skb_trim(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			/**
			 * ���û��ռ�����ں˿ռ��и�������skb
			 */
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			/**
			 * �Ѿ��������һ������������Ҫ�����䱨ͷ����չ��ͷ��ա�
			 */
			transhdrlen = 0;
			exthdrlen = 0;
			/**
			 * ֻ�в���Ƭʱ������ʹ��Ӳ��У��͵ķ�ʽ��
			 * �˴��޸�csummode��־�����������������һ��ѭ�������е�copy<=0�ķ�֧��˵�������˷�Ƭ����Ҫ����ΪCHECKSUM_NONE��
			 */
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			/**
			 * ���»������ӵ����������С� 
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		/**
		 * ���е����˵��copy > 0
		 * ����ζ��skb(sk_write_queue�����һ��Ԫ��)��һЩ���ÿռ䡣
		 * Ip_append_data��������Щ�ռ䡣�����ʣ�ռ䲻�㣨Ҳ����length���ڸÿ��ÿռ䣩����ѭ�����ٴε���������һ�λ������һ�����
		 */
		if (copy > length)
			copy = length;

		if (!(rt->u.dst.dev->features&NETIF_F_SG)) {/* ��֧�ַ�ɢ/�ۼ�IO */
			unsigned int off;

			off = skb->len;
			/**
			 * �������ݵ����������������С�
			 */
			if (getfrag(from, skb_put(skb, copy), 
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			/**
			 * �ϴη����ҳ���п���ռ䡣
			 */
			if (page && (left = PAGE_SIZE - off) > 0) {
				if (copy >= left)
					copy = left;
				if (page != frag->page) {
					if (i == MAX_SKB_FRAGS) {/* ����ҳ���������� */
						err = -EMSGSIZE;
						goto error;
					}
					/**
					 * skb_shinfo(skb)->frags[i]��ָ���ҳ�������Ҫ����ҳ�����ü�����
					 */
					get_page(page);
					/**
					 * skb_shinfo(skb)->frags[i]��ָ���ҳ��
					 */
	 				skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} else if (i < MAX_SKB_FRAGS) {/* �������ٷ���ҳ�� */
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  {
					err = -ENOMEM;
					goto error;
				}
				/**
				 * ��¼д��ҳ�漰��ʼλ�á�
				 */
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
				skb->truesize += PAGE_SIZE;
				atomic_add(PAGE_SIZE, &sk->sk_wmem_alloc);
			} else {/* �������ٷ���ҳ���� */
				err = -EMSGSIZE;
				goto error;
			}
			/**
			 * ��ȡ���ݱ���ָ����ҳ��λ�á�
			 */
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			sk->sk_sndmsg_off += copy;
			frag->size += copy;
			skb->len += copy;
			skb->data_len += copy;
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err; 
}

/**
 * ������֧�ַ�ɢ/�ۼ�IOʱ��ʵ��"0����"TCP/IP�õ��Ľӿڡ�
 * ��ip_append_data��Ӧ��
 * ��ǰ��UDPʹ�ã�TCP�ж�Ӧ�ĺ�����do_tcp_sendpage
 */
ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = inet->cork.rt;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;

	while (size > 0) {
		int i;

		/* Check if the remaining data fits into current packet. */
		len = mtu - skb->len;
		if (len < size)
			len = maxfraglen - skb->len;
		if (len <= 0) {
			struct sk_buff *skb_prev;
			char *data;
			struct iphdr *iph;
			int alloclen;

			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fragheaderlen + fraggap);
			skb->nh.iph = iph = (struct iphdr *)data;
			data += fragheaderlen;
			skb->h.raw = data;

			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				skb_trim(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		/**
		 * �ж��Ƿ������ϲ�
		 */
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;/* ֱ���޸���һ��frag�ϲ��� */
		} else if (i < MAX_SKB_FRAGS) {
			/**
			 * ����ҳ�������ͬʱ��skb_fill_page_desc�޸�frag
			 */
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			unsigned int csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
/**
 * ��L4�������ʱ�������sw_write_queue�����ЩƬ�Σ�ͨ��ip_append_data��ip_append_page�������������ʱ��Ҳ������Ϊĳ��Э���ض���׼�򣬻�����Ϊ�ϸ߲�Ӧ�ó���֪ͨ˵Ҫ�������ݣ����ͻ����ip_push_pending_frames��
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = inet->cork.rt;
	struct iphdr *iph;
	int df = 0;
	__u8 ttl;
	int err = 0;

	/**
	 * û����Ҫ���͵����ݡ��˳���
	 */
	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb->nh.raw)
		__skb_pull(skb, skb->nh.raw - skb->data);
	/**
	 * ���ѭ���Ǽ������з�Ƭ���ܳ���
	 */
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		__skb_pull(tmp_skb, skb->h.raw - skb->nh.raw);
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		__sock_put(tmp_skb->sk);
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	/**
	 * ����û����õı�־Ҫ�����PMTU���ң���ô��Ҫ��IPѡ���д���DF��־��
	 */
	if (inet->pmtudisc != IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. */
	/**
	 * ����DF��־��
	 */
	if (inet->pmtudisc == IP_PMTUDISC_DO || /* �׽���ϣ������PMTU���� */
	    (!skb_shinfo(skb)->frag_list && ip_dont_fragment(sk, &rt->u.dst)))
		df = htons(IP_DF);/* df��ӳ������"���ֶ�״̬" */

	/**
	 * ��ѡ�
	 */
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	/**
	 * ����Ƕಥ����ôttlһ����1��Ҳ�������û�ָ��ttl��
	 * ����ǵ�������ôttlĬ����64�����ǿ���ͨ��proc�޸�Ĭ��ֵ��
	 */
	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	/**
	 * ��׼��ͷ����Ϊ20���ֽڡ������ѡ����ڴ���ѡ��ʱ����ѡ��ĳ��ȡ�
	 */
	iph->ihl = 5;
	/**
	 * �����ͷ����IPѡ������ip_options_build������Щѡ�
	 * ��ip_options_build�����һ�����������0���Ը��߸�API����������д���ǵ�һ��Ƭ�ε�ѡ�
	 * �����������Ǳ�Ҫ�ģ���Ϊ��һ��Ƭ�ε�IPѡ����в�ͬ�ķ�ʽ��
	 */
	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}
	iph->tos = inet->tos;
	iph->tot_len = htons(skb->len);
	iph->frag_off = df;
	/**
	 * ���㱨��ID��
	 */
	if (!df) {
		__ip_select_ident(iph, &rt->u.dst, 0);	/* ���ݳ�ЧIP�˵����ID���㡣 */
	} else {
		iph->id = htons(inet->id++);/* �Բ��ֶܷεİ��������������ID����������Ϊ�˴���windows��һ��BUG�� */
	}
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;
	ip_send_check(iph);

	/**
	 * ��������ʹ��skb->priority������Ҫ�Ѹð�������һ�������С�
	 */
	skb->priority = sk->sk_priority;
	skb->dst = dst_clone(&rt->u.dst);

	/* Netfilter gets whole the not fragmented skb. */
	/**
	 * �ѻ���������dst_output����ɴ���֮ǰ���˺�������ȡ��netfilter��Ȩ�޲���������¡�
	 * ע�⣺ֻ��Ϊһ�����е�����Ƭ�β�ѯһ��netfilter��
	 */
	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, 
		      skb->dst->dev, dst_output);
	if (err) {
		if (err > 0)
			err = inet->recverr ? net_xmit_errno(err) : 0;
		if (err)
			goto error;
	}

out:
	/**
	 * ����֮ǰ���˺��������IPCORK_OPT�ֶΣ�ʹ��cork�ṹ������ʧЧ��
	 * ������Ϊ������ͬĿ�ĵصİ����ظ�ʹ��cork�ṹ.
	 */
	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
	return err;

error:
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset, 
			      int len, int odd, struct sk_buff *skb)
{
	unsigned int csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;  
}

/* 
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock 
 *     	structure to pass arguments.
 *
 *	LATER: switch from ip_build_xmit to ip_append_*
 */
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	u32 daddr;
	struct rtable *rt = (struct rtable*)skb->dst;

	if (ip_options_echo(&replyopts.opt, skb))
		return;

	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;

	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(skb->nh.iph->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = skb->h.th->dest,
					         .dport = skb->h.th->source } },
				    .proto = sk->sk_protocol };
		if (ip_route_output_key(&rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	inet->tos = skb->nh.iph->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = skb->nh.iph->protocol;
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((u16 *)skb->h.raw + arg->csumoffset) = csum_fold(csum_add(skb->csum, arg->csum));
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

/*
 *	IP protocol layer initialiser
 */
/**
 * ���ڽ�ETH_P_IP��Э�鴦����ע��Ϊip_rcv��
 * ip_init�����dev_add_pack(&ip_packet_type);ע��˽ṹ��
 */
static struct packet_type ip_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = ip_rcv,
};

/*
 *	IP registers the packet type and then calls the subprotocol initialisers
 */
/**
 * IPV4Э���ʼ��������
 */
void __init ip_init(void)
{
	/**
	 * ��dev_add_pack����ΪIP��ע�ᴦ�������˴������Ϊ��Ϊip_rcv�ĺ�����
	 */
	dev_add_pack(&ip_packet_type);

	/**
	 * ��ʼ��·����ϵͳ��������Э���޹صĻ��档
	 */
	ip_rt_init();
	/**
	 * ��ʼ�����ڹ���IP�˵�Ļ����ܹ���
	 */
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_finish_output);
EXPORT_SYMBOL(ip_fragment);
EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);

#ifdef CONFIG_SYSCTL
EXPORT_SYMBOL(sysctl_ip_default_ttl);
#endif
