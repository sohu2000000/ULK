/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <linux/config.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;
/**
 * ·�ɱ���������Э���޹صĲ��֣�DST����
 * ��������������Э�飨����IPv4,IPv6, DECnet����·�ɱ������ֶα����ڸýṹ�ڡ�
 * ������Э�����õ������ݽṹ�ڣ�ͨ��Ƕ��ýṹ����ʾ·�ɱ����
 */
struct dst_entry
{
	/**
	 * ���ڽ��ֲ���ͬһ����ϣͰ�ڵ�dst_entryʵ��������һ��
	 */
	struct dst_entry        *next;
	/**
	 * ���ü�����
	 */
	atomic_t		__refcnt;	/* client references	*/
	/**
	 * �ñ����Ѿ���ʹ�õĴ�������������ҷ��ظñ���Ĵ�������
	 */
	int			__use;
	/**
	 * ����IPSEC��ֻ�����һ��ʵ���е�input��output������ʵ��Ӧ����·�ɾ��ߣ�
	 * ǰ��ʵ���е�input��output������Ӧ������Ҫ���transformations��
	 */
	struct dst_entry	*child;
	/**
	 * Egress�豸�����������ʹ�Ŀ�ĵصķ����豸����
	 */
	struct net_device       *dev;
	/**
	 * ���ڶ����dst_entryʵ���Ŀ���״̬��0��ȱʡֵ����ʾ�ýṹ��Ч���ҿ��Ա�ʹ�ã�2��ʾ�ýṹ����ɾ��������ܱ�ʹ�ã�-1��IPsec��IPv6ʹ�õ�����IPv4ʹ�á�
	 */
	int			obsolete;
	/**
	 * ��־���ϡ�DST_HOST��TCPʹ�ã���ʾ����·�ɣ��������ǵ������һ���㲥/�ಥ��ַ��·�ɣ���
	 * DST_NOXFRM��DST_NOPOLICY��DST_NOHASHֻ����IPsec��
	 */
	int			flags;
#define DST_HOST		1
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
/**
 * ��DST����IPSECʱ��child�����з����һ��Ԫ�أ�������ʵ�ʵ�·�ɻ��棬������ô˱�־����ʾDST������HASH�С�
 */
#define DST_NOHASH		8
	/**
	 * ���ڼ�¼�ñ����ϴα�ʹ�õ�ʱ�����
	 * ��������ҳɹ�ʱ���¸�ʱ������������ճ���ʹ�ø�ʱ�����ѡ������ʵ�Ӧ�����ͷŵĽṹ��
	 */
	unsigned long		lastuse;
	/**
	 * ·�������ʱ�䣬Ĭ����������(ֵΪ0)��
	 */
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	/**
	 * metrics��������Ҫ��TCPʹ�á�
	 * ����������fib_info->fib_metrics������һ�ݿ�������ʼ�������fib_metrics���������壩������Ҫʱʹ��ȱʡֵ��
	 * ��Ҫ����һ��ֵRTAX_LOCK��RTAX_LOCK����һ��metric������һ������λͼ����λ��n�ı���λ������ʱ����ʾ�Ѿ�����lockѡ��/�ؼ���������ֵΪn��metric��
	 */
	u32			metrics[RTAX_MAX];
	/**
	 * ����IPSEC��ָ��child�����е����һ��Ԫ�ء�
	 */
	struct dst_entry	*path;

	/**
	 * ��һ��IMCP�ض�����Ϣ�ͳ���ʱ�����
	 */
	unsigned long		rate_last;	/* rate limiting for ICMP */
	/**
	 * �Ѿ������dst_entryʵ����ص�Ŀ�ĵط��͵�ICMP�ض�����Ϣ����Ŀ�����ԣ�rate_tokens-1��ʾĿ�ĵ��������Ե�ICMP�ض�����Ϣ����Ŀ��
	 */
	unsigned long		rate_tokens;

	/**
	 * ��fib_lookup API��ֻ��IPv4ʹ�ã�ʧ��ʱ������ֵ��������error����һ����ֵ���У��ں����ip_error��ʹ�ø�ֵ��������δ�����·�ɲ���ʧ�ܣ�������������һ��ICMP��Ϣ����
	 */
	int			error;

	/**
	 * neighbour�ǰ�����һ�������ַ�������ַӳ��Ľṹ��hh�ǻ���Ķ���ͷ��
	 */
	struct neighbour	*neighbour;
	struct hh_cache		*hh;
	struct xfrm_state	*xfrm;

	/**
	 * �ֱ��ʾ����ingress���ĺʹ���egress���ĵĺ�����
	 */
	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * ����·�ɱ��classifier�ı�ǩ��
	 */
	__u32			tclassid;
#endif

	/**
	 * �ýṹ�ڵ��麯����VFT�����ڴ���dst_entry�ṹ��
	 */
	struct  dst_ops	        *ops;
	/**
	 * �����⡣
	 */
	struct rcu_head		rcu_head;

	/**
	 * ���ֶ�����dst_entry���ݽṹβ����ָ������á���ֻ������ռλ��
	 */
	char			info[0];
};


/**
 * DST���Ĵ���ʹ���麯����������Э��֪ͨ�ض����¼���������·ʧЧ����
 * ÿ������Э������ṩһ�麯���������Լ��ķ�ʽ��������Щ�¼���
 * VFT��ÿһ���ֶβ����Ǳ����е�Э�鶼ʹ�á�
 */
struct dst_ops
{
	/**
	 * ��ַϵ�С�
	 */
	unsigned short		family;
	/**
	 * Э��ID��
	 */
	unsigned short		protocol;
	/**
	 * ���ֶ��������������㷨��ָ����·�ɻ��������������ϣͰ����Ŀ����
	 * ���ʼ������ip_rt_init��IPv4·����ϵͳ��ʼ������������ɵġ�
	 */
	unsigned		gc_thresh;

	/**
	 * �����������ա�����ϵͳͨ��dst_alloc������һ���µĻ��������ú��������ڴ治��ʱ�����������ա�
	 */
	int			(*gc)(void);
	/**
	 * dst_entry�����Ϊdead�Ļ���·����ͨ�����ٱ�ʹ�ã�����ʹ��IPsecʱ�ý��۲���һ��������
	 * ���������һ��obsolete dst_entry�Ƿ����á�
	 * ���ǣ�ipv4_dst_check������ɾ��dst_entry�ṹ֮ǰ����������Ƿ����ã�������Ӧ��xfrm_dst_check������Ҫ��IPsec��"xfrm"ת����
	 */
	struct dst_entry *	(*check)(struct dst_entry *, __u32 cookie);
	/**
	 * ��dst_destroy���ã�DST���иó�����ɾ��һ��dst_entry�ṹ������ɾ��֪ͨ����Э�飬�Ա����Э������һЩ��Ҫ����������
	 * ����IPv4����ipv4_dst_destroyʹ�ø�֪ͨ���ͷ��������ݽṹ�����á�
	 */
	void			(*destroy)(struct dst_entry *);
	/**
	 * ��dst_ifdown���ã���һ���豸���رջ�ע��ʱ��DST��ϵͳ����ú�����
	 * ��ÿһ����Ӱ��Ļ���·���Ҫ����һ�Ρ�
	 * IPv4����ipv4_dst_ifdown��һ��ָ��loopback�豸��ָ�����滻rtable��ָ���豸IP���õ�idevָ�룬������Ϊloopback�豸���Ǵ��ڡ�
	 */
	void			(*ifdown)(struct dst_entry *,
					  struct net_device *dev, int how);
	/**
	 * ��DST����dst_negative_advice���ã�����������DST֪ͨĳ��dst_entryʵ���������⡣
	 * ���統TCP��⵽һ��д������ʱʱʹ��dst_negative_advice��
	 * IPv4����ipv4_negative_adviceʹ�ø�֪ͨ��ɾ������·���
	 * �����dst_entry�Ѿ������Ϊdead��ipv4_negative_advice���ͷŵ���dst_entry��rtable���á�
	 */
	struct dst_entry *	(*negative_advice)(struct dst_entry *);
	/**
	 * ��DST����dst_link_failure���ã������ڷ��ͱ���ʱ���ڼ�⵽Ŀ�ĵز��ɴ�������
	 */
	void			(*link_failure)(struct sk_buff *);
	/**
	 * ���»���·�����PMTU��ͨ�����ڴ��������յ���ICMP��Ƭ������Ϣʱ���á�
	 */
	void			(*update_pmtu)(struct dst_entry *dst, u32 mtu);
	/**
	 * ���ظ�·��ʹ�õ�TCP���Σ�MSS����IPv4����ʼ���ó�������û����Ըú����ķ�װ����
	 */
	int			(*get_mss)(struct dst_entry *dst, u32 mtu);
	/**
	 * ����·�ɻ���ṹ���������IPv4�ĽṹΪrtable���Ĵ�С��
	 */
	int			entry_size;

	atomic_t		entries;
	/**
	 * ����·�ɻ���Ԫ�ص��ڴ�ء�
	 */
	kmem_cache_t 		*kmem_cachep;
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32
dst_path_metric(const struct dst_entry *dst, int metric)
{
	return dst->path->metrics[metric-1];
}

/**
 * ����һ��·�ɻ�����Ŀ����������PMTU��
 */
static inline u32
dst_pmtu(const struct dst_entry *dst)
{
	u32 mtu = dst_path_metric(dst, RTAX_MTU);
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return mtu;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

/**
 * ������ݼ�һ��dst_entry�����ü�����
 */
static inline void dst_hold(struct dst_entry * dst)
{
	atomic_inc(&dst->__refcnt);
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

/**
 * ������ݼ�һ��dst_entry�����ü�����
 */
static inline
void dst_release(struct dst_entry * dst)
{
	if (dst) {
		WARN_ON(atomic_read(&dst->__refcnt) < 1);
		smp_mb__before_atomic_dec();
		/**
		 * ������dst_release�ͷ����һ������ʱ���ñ�������Զ�ɾ����
		 */
		atomic_dec(&dst->__refcnt);
	}
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *dst_pop(struct dst_entry *dst)
{
	struct dst_entry *child = dst_clone(dst->child);

	dst_release(dst);
	return child;
}

extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

/**
 * dst_entry�ṹ��������Ƕ����rtable�ṹ�ڡ�������dst_entryʵ����ͨ������dst_free��ֱ��ɾ����
 */
static inline void dst_free(struct dst_entry * dst)
{
	/**
	 * ��һ��������Ȼ������ʱ���ܱ�ɾ��ʱ��������obsolete��־Ϊ2�������Ϊdead��dst->obsolete��ȱʡֵΪ0����
	 * ��ͼɾ��һ���Ѿ����Ϊdead�ı��ʧ�ܡ�
	 */
	if (dst->obsolete > 1)
		return;
	/**
	 * ������dst_freeɾ��һ�����ü���Ϊ0�ı�������dst_destroy����ɾ���ñ��
	 */
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		/**
		 * dst_destroy����Ҳ����ȥɾ�����ӵ��ýṹ���κ�children��
		 * ����һ��children������Ȼ�����ö����ܱ�ɾ��ʱ��dst_destroy����ָ���child��һ��ָ�룬��dst_free����������
		 */
		if (!dst)
			return;
	}
	/**
	 * ������dst_freeɾ��һ�����ü�����0�ı�������dst_destroy����ɾ��һ��childʱ��������������´���
 	 *		ͨ��������obsolete��־����Ǹñ���Ϊdead��
 	 *		���������Ӻ���dst_discard_in��dst_discard_out���滻�ñ���ԭ����input��output�����Դ���ȷ����ص�·�ɲ��ܹ����պͷ��ͱ��ġ����ִ���ʽ�����豸��û�д������л���down״̬��û������IFF_UP��־��ʱ�ĵ���������
 	 *		��dst_entry�ṹ��ӵ�dst_garbage_listȫ�������ڣ�����������Ӧ����ɾ���ģ����������ü�����0����û�б�ɾ���ı���������һ��
 	 *	 	����dst_gc_timer��ʱ���ڿ����õ���С�ӳ�ʱ�䣨DST_GC_MIN�����ڣ��ڸö�ʱ����û������ʱ��������
	 */
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}
/**
 * ȷ��ͨ�������ܹ�����Ŀ�ĵ�ַ��
 */
static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_negative_advice(struct dst_entry **dst_p)
{
	struct dst_entry * dst = *dst_p;
	if (dst && dst->ops->negative_advice)
		*dst_p = dst->ops->negative_advice(dst);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry * dst = skb->dst;
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

/**
 * ����·�������ʱ�䡣�������¼�����ʱ����:
 *		�����յ�һ��ICMP UNREACHABLE��FRAGMENTATION NEEDED��Ϣʱ���������·�����PMTU���뱻����ΪICMPͷ��ָ����MTU��ICMP���Ĵ������ip_rt_frag_needed������·�ɻ��档��Щ��Ӱ��ı����ڿ����õ�ʱ��ip_rt_mtu_expires֮������Ϊ���ڣ����ʱ��ֵȱʡΪ10����
 *		��TCP������·��MTU�����㷨������һ��·�ɵ�MTUʱ������ip_rt_update_pmtu�������ú���������dst_set_expires��
 *		��һ��Ŀ��IP��ַ����Ϊ���ɴ�ʱ��ͨ��ֱ�ӻ��ӵ���dst_ops���ݽṹ�е�link_failure����������������ص�dst_entry�ṹ���Ϊ���ɴ�
 */
static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  */
/**
 * ���д��䣨�����Ǳ��ز����Ļ��Ǵ���������ת������������ͨ��dst_output���У��Ե���Ŀ��������
 * ��ʱ��IP��ͷ�Ѿ���ɣ��ں���������Ҫ����Ϣ�Լ�����ϵͳҪ������ӵ������κ���Ϣ��
 */
static inline int dst_output(struct sk_buff *skb)
{
	int err;

	for (;;) {
		/**
		 * ���Ŀ�ĵ�ַ�ǵ����ģ����ʼ��Ϊip_output������Ƕಥ�ģ�����ʼ��Ϊip_mc_output
		 * �ֶ�Ҳ���ڸú����ڴ���ġ�
		 * �������ip_finish_output�������ھ���ϵͳ
		 */
		err = skb->dst->output(skb);

		if (likely(err == 0))
			return err;
		/**
		 * ���IPSEC����NET_XMIT_BYPASS����ʾ��Ҫ������ν���output��
		 */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	int err;

	for (;;) {
		err = skb->dst->input(skb);

		if (likely(err == 0))
			return err;
		/* Oh, Jamal... Seems, I will not forgive you this mess. :-) */
		if (unlikely(err != NET_XMIT_BYPASS))
			return err;
	}
}

extern void		dst_init(void);

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags)
{
	return 0;
} 
#else
extern int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		       struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */
