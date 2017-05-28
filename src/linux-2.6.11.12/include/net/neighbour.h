#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

/* The following flags & states are exported to user space,
   so that they should be moved to include/linux/ directory.
 */

/*
 *	Neighbor Cache Entry Flags
 */

#define NTF_PROXY	0x08	/* == ATF_PUBL */
#define NTF_ROUTER	0x80

/*
 *	Neighbor Cache Entry States.
 */
/**
 * �շ������Ѿ����ͣ�������δ�յ���Ӧʱ������״̬�������״̬�£�������ʹ���κ�Ӳ����ַ.
 */
#define NUD_INCOMPLETE	0x01
/**
 * �ھӵ�ַ�����棬���������֪�ǿɴ��
 */
#define NUD_REACHABLE	0x02
/**
 * �⼸����Ǩ�Ƶ��м�״̬�������������ж��ھ��Ƿ�ɴ�Ĺ�����������Щ״̬��
 */
#define NUD_STALE	0x04
#define NUD_DELAY	0x08
#define NUD_PROBE	0x10
/**
 * �����շ�����ʧ�ܶ�����ھ��ǲ��ɴ�״̬������������Ŀʱ���ɵĺ���NUD_PROBE�������շ�����ʧ�ܡ�
 */
#define NUD_FAILED	0x20

/* Dummy states */
/**
 * ���״̬���ڱ���ھӲ���Ҫ�κ�Э��������L3�㵽L2��ĵ�ַӳ��ת��
 */
#define NUD_NOARP	0x40
/**
 * L2���ھӵ�ַ����̬����ʱ��״̬��(���û��ռ���������)�����Բ���Ҫ�κ��ھ�Э�鿼������
 */
#define NUD_PERMANENT	0x80
/**
 * ��ʾ�ھ���Ŀ����������Ŀǰ�в����á�
 */
#define NUD_NONE	0x00

/* NUD_NOARP & NUD_PERMANENT are pseudostates, they never change
   and make no address resolution or NUD.
   NUD_PERMANENT is also cannot be deleted by garbage collectors.
 */

#ifdef __KERNEL__

#include <asm/atomic.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>

/**
 * ��ʾ�ھ���ϵͳΪ�ھ���Ŀ�ṩ��һ���������еĶ�ʱ�����ⷢ�������ھ���Ŀ״̬��ȷ��ʱ��
 * �������״̬�Ļ���״̬�ǣ�NUD_INCOMPLETE��NUD_DELAY��NUD_PROBE
 */
#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
/**
 * ���һ���ھ���Ŀ��״̬����������״̬�е�һ����������϶�����NUD_VALID״̬��
 * ������ھ�ȷ��������һ�����õ�ַ������NUD_PERMANENT��NUD_NOARP��NUD_REACHABLE��NUD_PROBE��NUD_STALE��NUD_DELAY
 */
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
/**
 * ���״̬��NUD_VALID���Ӽ�������û��δ����ȷ�ϴ���.
 * �����¼���״̬����ʾ����NUD_CONNECTED״̬��NUD_PERMANENT��NUD_NOARP��NUD_REACHABLE
 */
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

/**
 * ��ÿ���豸���ھ�Э����Ϊ���е�����һ�������
 * �����ڴ󲿷ֽӿ��Ͽ����������Э�飨��IPV4��IPV6��������һ��net_device�ṹ���Թ������neigh_parms�ṹ��
 */
struct neigh_parms
{
	/**
	 * ���ӵ���ͬһ��Э��ع�����neigh_parmsʵ����ָ�롣��˼����˵ÿ��neigh_table�ṹ�������Լ���neigh_parms�ṹ�б�ÿ��ʵ����Ӧ��һ�����õ��豸��
	 */
	struct neigh_parms *next;
	/**
	 * ������Ȼʹ�þ��ھӻ����ṹ���豸����Ҫʹ�������������ʼ����
	 * ͨ�����ú���ֻ���ڽ�neighbour->ops��ʼ��Ϊarp_broken_ops��
	 */
	int	(*neigh_setup)(struct neighbour *);
	/**
	 * ����ָ�룬ָ����иýṹ��neigh_table�ṹ��
	 */
	struct neigh_table *tbl;
	int	entries;
	/**
	 * �ݲ�ʹ�á�
	 */
	void	*priv;

	/**
	 * �������net/ipv4/neighbour.c�ļ��еĽ�β�ĳ�������ɳ�ʼ�������������û��޸�neigh_parms�ṹ�е�ĳЩ������ֵ�йء�
	 */
	void	*sysctl_table;

	/**
	 * ����һ��������ʶ�����ú��ʾ���ھ�ʵ������"��ɾ��"��
	 */
	int dead;
	/**
	 * ���ü�����
	 */
	atomic_t refcnt;
	/**
	 * ��������⡣
	 */
	struct rcu_head rcu_head;

	/**
	 * base_reachable_time��һ��ʱ��������jiffies��ʾ������ʾ�Դ����һ���յ��ɵ�����֤���󾭹���ʱ�䡣
	 * ע�⣬�����������ڼ���ʵ��ʱ���һ������ֵ��ʵ��ʱ�䱣����reachable_time�С�
	 * ʵ��ʱ����base_reachable_time��3/2base_reachable_time֮���һ�����ֵ�����ȷֲ�����
	 * ������ֵÿ300����neigh_periodic_timer����һ�Σ�����Ҳ�����������¼����¡�
	 */
	int	base_reachable_time;
	/**
	 * ��һ̨������retrans_timeʱ����û���յ�solicitation�����Ӧ��ʱ���ͻᷢ��һ���µ�solicitation����һֱ���Դ����������ֵ��
	 * retrans_timeҲ����jiffies��ʾ��
	 */
	int	retrans_time;
	/**
	 * ���һ��neighbour�ṹ��gc_staletimeʱ���ڻ�û�б�ʹ�ù�������û�г�������������ô���ͻᱻɾ����
	 * gc_staletime����jiffies��ʾ�ġ�
	 */
	int	gc_staletime;
	int	reachable_time;
	/**
	 * �������������һ���ھ��ڽ���NUD_PROBE̬ǰ����NUD_DELAY̬�ȴ��೤ʱ�䡣
	 */
	int	delay_probe_time;

	/**
	 * arp_queue�����������ɵ�Ԫ�ص������Ŀ��
	 */
	int	queue_len;
	/**
	 * ucast_probes��ʾΪ��֤ʵһ����ַ�Ŀɵ����ԣ��ܷ��͵ĵ���solicitations������
	 */
	int	ucast_probes;
	/**
	 * app_probes���û��ռ�����ڽ���һ����ַʱ�����Է��͵�solicitations��������
	 */
	int	app_probes;
	/**
	 * mcast_probes��ʾΪ�˽���һ���ھӵ�ַ�����Է����Ķಥsolicitation��������
	 * ��ARP/IPV4��˵����ʵ�ʾ��ǹ㲥solicitation����Ŀ����ΪARP��ʹ�öಥsolicitation������IPV6Ҫʹ�öಥ��
	 */
	int	mcast_probes;
	/**
	 * �ݲ�ʹ�á�
	 */
	int	anycast_delay;
	/**
	 * �ھ�Э����ڴ�����ǰ���ڴ��������Ӧ�ñ����ʱ�䡣
	 * �����ӳ�ʱ�䡣ʵ�ʵ��ӳ�ʱ�����0��proxy_delay֮�䡣
	 * �������ʹ�ÿ��Խ��Ͷ������ͬʱ�������󣬲�����ӵ���Ŀ����ԡ�
	 */
	int	proxy_delay;
	/**
	 * ��ʱ�洢���е���󳤶ȡ�
	 * proxy_queue�����������ɵ�Ԫ�ص������Ŀ��
	 */
	int	proxy_qlen;
	/**
	 * �����ڣ����յ���һ��ARPOP_REPLYʱ��������ͬһ��ARPOP_REQUEST�ĵڶ���ARPOP_REPLY��locktime�ڵ�ʱ�䵽���ڶ������ᱻ���ԡ�
	 */
	int	locktime;
};

/**
 * �ھ�Э���ͳ�����ݡ�
 */
struct neigh_statistics
{
	/**
 	 * �ھ�Э������neighbour�ṹ��������������Щ�Ѿ���ɾ����neighbour�ṹ��
 	 */
	unsigned long allocs;		/* number of allocated neighs */
	/**
	 * ɾ����neighbour�����Ŀ����neigh_destroy����������¡�
	 */
	unsigned long destroys;		/* number of destroyed neighs */
	/**
	 * hash���������ӵĴ�������neigh_hash_grow����������¡�
	 */
	unsigned long hash_grows;	/* number of hash resizes */

	/**
	 * ����һ���ھӵ�ַʶ����ԵĴ�����ÿ���ͳ�һ���µ�solicitation���������������ֵ��ֻ�е����еĳ���ʧ�ܺ󣬲Ż���neigh_timer_handler��������ֵ������
	 */
	unsigned long res_failed;	/* nomber of failed resolutions */

	/**
	 * ����neigh_lookup�����Ĵ�����
	 */
	unsigned long lookups;		/* number of lookups */
	/**
	 * neigh_lookup������ѯ�ɹ��Ĵ�����
	 */
	unsigned long hits;		/* number of hits (among lookups) */

	/**
	 * �������ֶ�ֻ��IPV6ʹ�ã���ʾ�յ���solicitation����������������ֶηֱ��ʾ�ಥ��ַ�͵�����ַ����
	 */
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	/**
	 * neigh_periodic_timer��neigh_forced_gc���Ա����õĴ�����
	 */
	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

/**
 * �洢�ھӵ��й���Ϣ�����磬L2��L3��ַ��NUD״̬�����ʸ��ھӾ������豸�ȡ�
 * һ��neighbour�����һ̨�����йأ�������һ��L3��ַ�йء�
 */
struct neighbour
{
	/**
	 * ÿ��neighbour����뵽һ��hash���С�Nextָ����һ��neighbour�ṹ������ṹ�뵱ǰ�ṹ��ͻ�ҹ���ͬһ��bucket��
	 * ��Ԫ�����ǲ��뵽bucket�б�ı�ͷ��
	 */
	struct neighbour	*next;
	/**
	 * ָ��neigh_table�ṹ��ָ�룬����ṹ�������뵱ǰ�ھ����йص�Э�顣
	 * ���磬����ھ�ʹ��һ��IPV4��ַ��tbl��ָ��arp_tbl�ṹ��
	 */
	struct neigh_table	*tbl;
	/**
	 * ���ڵ����ھ�Э����Ϊ�Ĳ�����������һ��neighbour�ṹʱ����Ƕ�뵽��Э����ص�neigh_table�ṹ�е�neigh_parms�ṹ��Ĭ��ֵ��ʼ��parms��
	 */
	struct neigh_parms	*parms;
	/**
	 * ͨ������豸�����Է��ʸ��ھӡ�ÿ���ھ�ֻ��ͨ��һ���豸�����ʡ�
	 * ��ֵ����ΪNULL����Ϊ�������ں���ϵͳ�У�NULLֵ��ʾͨ�������ʾ�����豸��
	 */
	struct net_device		*dev;
	/**
	 * �ھ������һ�α�ʹ�õ�ʱ�䡣���ֵ�����������ݴ����ͬ�����¡�
	 * �����ھ��û�е�NUD_CONNECTED̬ʱ������ֶ���neigh_resolve_ouput��������neigh_event_send�����¡�
	 * ��Ӧ�ģ����ھ������NUD_CONNECTED̬ʱ������ֵ��neigh_periodic_timer����Ϊ���ھ���Ŀɵ����������֤ʵ��ʱ�䡣
	 */
	unsigned long		used;
	/**
	 * ʱ�������jiffies��ʾ����ʾ���ھӵĿɵ����������֤����ʱ�䡣
	 * L4Э����neigh_confirm�����������ֵ���ھӻ���Э����neigh_update��������
	 */
	unsigned long		confirmed;
	/**
	 * �ھ������ʱ�䣬��ֹ����յ�ARPOP_REPLYʱ�������ظ�����
	 * һ��ʱ�������ʾneigh_update�������һ�θ��¸��ھӵ�ʱ�䣨�״γ�ʼ��ʱ����neigh_alloc�������ã���
	 * ��Ҫ��updated��confirmed�������������ֶα�ʾ��ͬ���¼���
	 * ���ھӵ�״̬�ı�ʱ��Ҫ����updated�ֶΣ���confirmed�ֶ�ֻ��¼�ھ������һ��״̬�ı䣺���ھ����һ��֤������Чʱ��������״̬�ı䡣
	 */
	unsigned long		updated;
	/**
	 * ����ֶεĿ�ѡֵ��include/linux/rtnetlink.h��include/net/neighbour.h�У�
	 */
	__u8			flags;
	/**
	 * ָʾ�ھ����״̬�����ܵ�ȡֵ��NUD_XXX��ʽ��������������include/net/neighbour.h��include/linux/rtnetlink.h�С�
	 */
	__u8			nud_state;
	/**
	 * ��neigh_create��������Э���constructor���������ھ���ʱ���ͻ���������ֶΡ�
	 * ����ֵ�������ڸ��ֳ��ϣ����磬������Щֵ���Ը���nud_state��
	 */
	__u8			type;
	/**
	 * ���dead����Ϊ1����ʾ�ýṹ����ɾ����������ʹ���ˡ�
	 */
	__u8			dead;
	/**
	 * ʧ�ܵ�solicitation���ԵĴ���������ֵ��neigh_timer_handler��ʱ����⡣�����Դ���������������ֵʱ�������ʱ���ͽ���neighbour��ת�Ƶ�NUD_FAILED̬��
	 */
	atomic_t		probes;
	/**
	 * �����ڳ��־���ʱ��neighbour�ṹ���б�����
	 */
	rwlock_t		lock;
	/**
	 * ��primiary_key��ʾ��L3��ַ������L2��ַ����ethernet NIC��Ethernet MAC��ַ���������ַ�Ƕ����Ƹ�ʽ������ha�ĳ�����MAX_ADDR_LEN��32�����������뵽C����long���͵�һ����
	 */
	unsigned char		ha[(MAX_ADDR_LEN+sizeof(unsigned long)-1)&~(sizeof(unsigned long)-1)];
	/**
	 * �����L2֡ͷ�б�
	 */
	struct hh_cache		*hh;
	/**
	 * ���ü�����
	 */
	atomic_t		refcnt;
	/**
	 * �������ھӷ���֡�ĺ���������һЩ���أ��������ָ��ʵ��ָ��ĺ����ڸýṹ���������ڿ��Ըı��Ρ�
	 * ���ھ����״̬ΪNUD_REACHABLE̬��NUD_STALE̬ʱ�����Էֱ�ͨ������neigh_connect��neigh_suspect�������¸��ֶε�ֵ��
	 */
	int			(*output)(struct sk_buff *skb);
	/**
	 * Ŀ��L3��ַ��û�б������İ�����ʱ�ŵ���������С���Ҫ��������е����ƣ����ܱ������ھ�Э��ʹ�ã���ֻ��ARP��
	 *
	 * ������һ�����ݰ�ʱ�����Ŀ��L3��ַ��L2��ַ֮��Ĺ�����û�н������ھ�Э�齫�ð���ʱ�嵽arp_queue������
	 * ͨ��ֻ������Ԫ�أ������Ԫ�ػὫ��Ԫ���滻��
	 * Ҳ�������ó��豸�����˶��С�
	 */
	struct sk_buff_head	arp_queue;
	/**
	 * ���ڴ���������Ķ�ʱ����
	 */
	struct timer_list	timer;
	/**
	 * VFT�а����ĸ��ַ�������������ά��neighbour�
	 */
	struct neigh_ops	*ops;
	/**
	 * ���ھӵ�L3��ַ������Ϊ������ҵĹؼ��֡���ARP����˵������һ��IPV4��ַ����ND��˵������һ��IPV6��ַ��
	 */
	u8			primary_key[0];
};

/**
 * һ�麯����������ʾL3Э�飨��IP����dev_queue_xmit֮��Ľӿڡ�
 * ��Щ���⺯�����Ը�������ʹ�õ������Ļ������ı䡣
 */
struct neigh_ops
{
	/**
	 * ��ַ�ء�
	 */
	int			family;
	/**
	 * ��һ��neighbour��Ҫ��neigh_destroyɾ��ʱ����ִ�иú�����
	 * ����������neigh_table->constructor�����Ļ���������������ĳЩԭ��contructorλ��neigh_table�ṹ�У���destructorλ��neigh_ops�ṹ�С�
	 */
	void			(*destructor)(struct neighbour *);
	/**
	 * ����solicitation����ĺ�����
	 */
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	/**
	 * ��һ���ھӱ���Ϊ���ɵ���ʱ��Ҫ�������������
	 */
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/**
	 * ���������ͨ�ĺ������������е�����¡��������ַ�Ƿ��Ѿ�����������
	 * ��û�б�����������£����������������������ַ��û��׼���ã�����Ѱ�������һ����ʱ�����У���������������
	 * ���ڸú���Ϊ�˱�֤���շ��ǿɵ���ģ�������ÿ����Ҫ�����飬����������˵��Ҫ�Ĳ����Ƚ϶ࡣ
	 * ��Ҫ��neigh_ops->output��neighbour->output�������
	 */
	int			(*output)(struct sk_buff*);
	/**
	 * ���Ѿ�֪���ھ��ǿɵ���ʱ���ھ�״̬ΪNUD_CONNECTED̬����ʹ�øú�������Ϊʹ����Ҫ����Ϣ��������ģ��ú���ֻҪ�����һ��L2֡ͷ���������output�ٶ�Ҫ�졣
	 */
	int			(*connected_output)(struct sk_buff*);
	/**
	 * ����ַ�ѱ�������������������ͷ�Ѿ�������һ�δ���ṹ����֡ͷ����ʱ����ʹ�����������
	 */
	int			(*hh_output)(struct sk_buff*);
	/**
	 * ǰ��ĺ����У�����hh_output�⣬������ʵ�ʴ���������������Ĺ�������ȷ����ͷ�Ǳ�д�õģ�Ȼ�󵱻�����׼����ʱ������queue_xmit���������䡣
	 */
	int			(*queue_xmit)(struct sk_buff*);
};

/**
 * ����Ŀ�ĵ�ַ�Ĵ���
 */
struct pneigh_entry
{
	struct pneigh_entry	*next;
	struct net_device		*dev;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

/**
 * ����һ���ھ�Э��Ĳ��������ú�����ÿ���ھ�Э�鶼�иýṹ��һ��ʵ����
 * ����ʵ�������뵽һ���ɾ�̬����neigh_tablesָ���һ��ȫ�ֱ��У�����neight_tbl_lock�����Ա���������ֻ�ᱣ��ȫ�ֱ�������ԣ������Ա���ÿ����Ŀ�����ݽ��б�����
 */
struct neigh_table
{
	/**
	 * �����е�Э������ӵ�һ�������С�
	 */
	struct neigh_table	*next;
	/**
	 * �ھ�Э������ʾ���ھ���ĵ�ַ�ء�
	 * ���Ŀ���ȡֵλ��include/linux/socket.h�ļ��У����ƶ���AF_XXX����ʽ��
	 * ����IPV4��IPV6����Ӧ��ֵ�ֱ���AF_INET��AF_INET6��
	 */
	int			family;
	/**
	 * ���뵽�����е����ݽṹ�ĳ��ȡ�����һ��neighbour�ṹ����һ���ֶΣ����ĳ���������Э���йأ�primary_key����
	 * Entry_size�ֶε�ֵ����һ��neighbour�ṹ���ֽ�����Э���ṩ��primary_key�ֶε��ֽ���֮��
	 */
	int			entry_size;
	/**
	 * ���Һ���ʹ�õĲ��ҹؼ��ֵĳ��ȡ�
	 * ���ڲ��ҹؼ�����һ��L3��ַ����IPV4��˵�����ֶε�ֵ����6��
	 * ��IPV6��˵������8��
	 * ��DECnet��˵������2��
	 */
	int			key_len;
	/**
	 * hash�������ڲ���һ���ھ���ʱ���ú����������ؼ��ִ�hash����ѡ����ȷ��buchet��
	 */
	__u32			(*hash)(const void *pkey, const struct net_device *);
	/**
	 * ������һ���µ��ھ���ʱ��neigh_create�������õ�constructor������
	 * �÷������ʼ����neighbour����Э��ָ����һЩ�ֶΡ�
	 */
	int			(*constructor)(struct neighbour *);
	/**
	 * pconstructor��Ӧ��constructor�����ڣ�ֻ��ipv6ʹ��pconstructor��
	 */
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	/**
	 * �����������ĺ�����
	 * ��solicit����Ӵ������neigh_table->proxy_queue��ȡ���󣬴��������ĺ�����
	 */
	void			(*proxy_redo)(struct sk_buff *skb);
	/**
	 * ��ֻ��һ�����ڱ�ʶЭ����ַ������ڷ����ڴ��ʱ���μ�neigh_table_init��������ڴ�����ڷ���neighbour�ṹ�����ֶ���Ҫ��Ϊһ��ID��
	 */
	char			*id;
	/**
	 * ������ݽṹ������һЩ���ڵ����ھ�Э����Ϊ�Ĳ�����
	 */
	struct neigh_parms	parms;
	/* HACK. gc_* shoul follow parms without a gap! */
	/**
	 * ���������������gc_timer��ʱ����ûᳬʱ���������������ա�
	 */
	int			gc_interval;
	/**
	 * ������ֵ������������ͬ������ڴ�״̬���ھ�Э��ɽ���Щ״̬������ǰ�����е�neighbour�
	 */
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	/**
	 * ���������ʾneigh_forced_gc���һ��ִ�е�ʱ�䣬��jiffies������
	 * ���仰˵������ʾ�����ڴ治�㣬���һ���������ճ���ִ�е�ʱ�䡣
	 */
	unsigned long		last_flush;
	/**
	 * �������ն�ʱ����
	 */
	struct timer_list 	gc_timer;
	/**
	 * ����ִ�д�����ʱ�Ķ�ʱ����
	 * ��ʱ����neigh_table_init��ʼ����Ĭ�ϴ�������neigh_proxy_process��
	 * ��proxy_queue������������һ��Ԫ��ʱ���ͻ����������ʱ����
	 * �����ʱ����ʱ��ִ�еĴ�����ʱneigh_proxy_process��
	 * ��neigh_table_init������Э���ʼ��ʱ�������ʱ����ʼ����
	 * ����neigh_table->gc_timer��ʱ����ͬ������������������
	 * ֻ����Ҫ��ʱ�����������磬����proxy_queue���״�����һ��Ԫ��ʱ��Э��ͻ�����������
	 */
	struct timer_list 	proxy_timer;
	/**
	 * Э��˽�е���ʱ������solicitation����Ķ��С�
	 * ���������������˷ǿյ�proxy_delay�ӳ�ʱ���յ���solicit������ARP���յ�ARPOP_REQUEST�����ͷŵ���������С���Ԫ�ر��ӵ���β��
	 */
	struct sk_buff_head	proxy_queue;
	/**
	 * ��Э�黺���е�ǰneighbour�ṹʵ������Ŀ��
	 * ÿ����neigh_alloc����һ���µ��ھ������ֵ������1����neigh_destroy�ͷ�һ���ھ������ֵ�ͼ�1��
	 */
	atomic_t		entries;
	/**
	 * �����ڳ��־���ʱ��������������
	 * ����ֻ��Ҫ��Ȩ�޵ĺ��������磬neigh_lookup����������ֻ��ģʽ�������������������磬neigh_periodic_timer�������Դ��ڶ�/дģʽ��
	 */
	rwlock_t		lock;
	/**
	 * ��һ����ÿ���豸��������һ����������neigh_parms�ṹ������reachable_time��������µ�ʱ�䡣
	 */
	unsigned long		last_rand;
	/**
	 * û��ʹ�á�
	 */
	struct neigh_parms	*parms_list;
	/**
	 * ����neighbour�ṹʱ��Ҫ���ڴ�ء�����ڴ����Э���ʼ��ʱ����neigh_table_init����ͳ�ʼ����
	 */
	kmem_cache_t		*kmem_cachep;
	/**
	 * �����е�neighbourʵ���ĸ���ͳ����Ϣ��
	 */
	struct neigh_statistics	*stats;
	/**
	 * ����Э���������L3��L2��ӳ���̬���á�
	 * �洢neighbour���hash��
	 */
	struct neighbour	**hash_buckets;
	/**
	 * hash��ĳ��ȡ�
	 */
	unsigned int		hash_mask;
	/**
	 * �����泤��Ҫ����ʱ�����ڷַ�neighbour��������ֵ��
	 */
	__u32			hash_rnd;
	/**
	 * ��¼�������е��������ն�ʱ��Ҫɨ���hash���е���һ��bucket����Щbucket�ǰ�˳��ɨ��ġ�
	 */
	unsigned int		hash_chain_gc;
	/**
	 * �洢Ҫ�������L3��ַ�ı�
	 * ��Ŀ�ĵؽ��д���ʱ��������Ҫ�������IP��ַ��
	 * û���������ƣ�����Ҳû���������ջ��ơ�
	 * ��IPV4�У���Щ��ַֻ���ֶ����á�
	 */
	struct pneigh_entry	**phash_buckets;
#ifdef CONFIG_PROC_FS
	/**
	 * ע�ᵽ/proc/net/stat�е��ļ����������Э���ͳ����Ϣ��
	 */
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
/**
 * ָ��ǰ��L2��ַ���Ա�lladdr���ǡ�
 * �����Ըı�ʹ�������ʶ������replace��add���
 * Э��������ʹ�������ʶ����һ��L2��ַ�趨һ����С�����ڡ�
 */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
/**
 * �������������ṩ����·���ַlladdr�뵱ǰ��֪���ھ�neigh->ha����·���ַ��ͬ����ô�����ַ���ǿ��ɵģ�Ҳ����˵���ھӵ�״̬��ת�Ƶ�NUD_STALE���Ա㴥���ɵ�������֤����
 */
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
/**
 * ��ʾIPV6 NTF_ROUTER��ʶ���Ա�����
 */
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
/**
 * ��ʾ����ھ��Ǹ�·�����������ʶ���ڳ�ʼ��neighbour->flags�е�IPV6��ʶNTF_ROUTER��
 */
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
/**
 * �����Ըı䡣��˼��˵�ı��������û��ռ����
 */
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern void neigh_app_ns(struct neighbour *n);

extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

/**
 * �ͷŶ��ھӻ���������á�ɾ��neighbour�ṹ��ԭ����Ҫ������������
 *		�ں���ͼ��һ�����ɵ�����������Ͱ���
 *		����ھӽṹ������������L2��ַ�ı��ˣ���������������NIC����������L3��ַ����ԭ���ġ�
 *		���ھӽṹ����ʱ��̫�������ں���Ҫ����ռ�õ��ڴ档���ʹ���������ս���ɾ����
 */
static inline void neigh_release(struct neighbour *neigh)
{
	/**
	 * ֻ�е�һ���ṹ�����ü�����Ϊ0ʱ���Ż�ɾ���ýṹ��
	 */
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)
/**
 * �����ھӻ���������á�
 */
static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		/**
		 * �ı��ھӻ����ʱ��������ǲ����ı��ھ�״̬��
		 * ����ʱ����⵽һ���µ�ʱ�����ʱ�����ͻ�ı���ص��ھ�״̬��
		 */
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}
/**
 * ��neigh_lookip����ʧ�ܺ͸ú��������������������creat��־ʱ���ú�����ʹ��neigh_create����������һ��neighbour�
 */
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

/**
 * �ú���ʹ��neigh_lookup�������鿴Ҫ���ҵ��ھ����Ƿ���ڣ����ҵ�����ʧ��ʱ�����Ǵ���һ����neighbourʵ����
 * ���˲���Ҫ����creat��ʶ�⣬�ú��������Ϻ�__neigh_lookup������ͬ��
 */
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

#define LOCALLY_ENQUEUED -2

#endif
#endif


