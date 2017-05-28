/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <linux/config.h>
#include <net/flow.h>
#include <linux/seq_file.h>

/* WARNING: The ordering of these elements must match ordering
 *          of RTA_* rtnetlink attribute numbers.
 */
/**
 * ���ں˽��յ������û��ռ���һ��IPROUTE2����Ҫ����ӻ�ɾ��һ��·��ʱ���ں˽������󲢴洢��kern_rta�ṹ��.
 */
struct kern_rta {
	void		*rta_dst;
	void		*rta_src;
	int		*rta_iif;
	int		*rta_oif;
	void		*rta_gw;
	u32		*rta_priority;
	void		*rta_prefsrc;
	struct rtattr	*rta_mx;
	struct rtattr	*rta_mp;
	unsigned char	*rta_protoinfo;
	u32		*rta_flow;
	struct rta_cacheinfo *rta_ci;
	struct rta_session *rta_sess;
};

struct fib_info;

/**
 * ��һ����
 * ���ʹ������ip route add 10.0.0.0/24 scope global nexthop via 192.168.1.1�����һ��·�ɣ���ô��һ��Ϊ192.168.1.1��
 * һ��·�ɱ���һ��ֻ��һ����һ���������ں�֧�ֶ�·������ʱ����ô���Ϳ��Զ�һ��·�������ö����һ����
 */
struct fib_nh {
	/**
	 * �������豸��ʶnh_oif�������������������net_device���ݽṹ��
	 * ��Ϊ�豸��ʶ��ָ��net_device�ṹ��ָ�붼��Ҫ���ã��ڲ�ͬ���������ڣ������������������fib_nh�ṹ�У���Ȼ���������κ�һ��Ϳ��Եõ���һ�
	 */
	struct net_device	*nh_dev;
	/**
	 * ���ڽ�fib_nh���ݽṹ���뵽��ϣ���С�
	 */
	struct hlist_node	nh_hash;
	/**
	 * ��ָ��ָ�������fib_nhʵ����fib_info�ṹ��
	 */
	struct fib_info		*nh_parent;
	/**
	 * ��һ����־����RTNH_F_DEAD��RTNH_F_ONLINK��
	 */
	unsigned		nh_flags;
	/**
	 * ���ڻ�ȡ��һ����·��scope���ڴ���������ΪRT_SCOPE_LINK�����ֶ���fib_check_nh����ʼ����
	 */
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * ��һ����Ȩֵ�����û�û����ȷ����ʱ������Ϊȱʡֵ1��
	 */
	int			nh_weight;
	/**
	 * ʹ����һ����ѡ�е�tokens�����ֵ���ڳ�ʼ��fib_info->fib_powerʱ�����ȱ���ʼ��Ϊfib_nh->nh_weight��
	 * ÿ��fib_select_multipathѡ�и���һ��ʱ�͵ݼ���ֵ��
	 * �����ֵ�ݼ�Ϊ��ʱ������ѡ�и���һ����ֱ��nh_power�����³�ʼ��Ϊfib_nh->nh_weight�����������³�ʼ��fib_info->fib_powerֵʱ���еģ���
	 */
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	/**
	 * ·��realm��
	 * һ������£�ֻʹ��Ŀ��realm������·�ɱ�ǩ������Ŀ�ĵ�ַ��ѡ��ƥ��·�ɡ�
	 * ���ǣ��ں���ʱ����Ҫ����·�����ҡ��������������ʱ��·�����Ŀ��realm�Ǵӷ���·�ɵ�Դrealm�ó��ġ�nh_tclassid��һ��32���ر�����
	 */
	__u32			nh_tclassid;
#endif
	/**
	 * egress�豸��ʶ���������ùؼ���oif��dev�����õġ�
	 */
	int			nh_oif;
	/**
	 * ��һ�����ص�IP��ַ���������ùؼ���via�����õġ�
	 */
	u32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */

/**
 * ��ͬ·�ɱ���֮����Թ���һЩ��������Щ�������洢��fib_info���ݽṹ�ڡ�
 * ��һ���µ�·�ɱ������õ�һ�������һ���Ѵ��ڵ�·�������õĲ���ƥ�䣬�����Ѵ��ڵ�fib_info�ṹ��
 * һ�����ü������ڸ����û�������
 */
struct fib_info {
	/**
	 * ���ṹ���뵽fib_info_hash���С�ͨ��fib_find_info�ӿ������Ҹñ�
	 */
	struct hlist_node	fib_hash;
	/**
	 * ���ṹ���뵽fib_info_laddrhash���С���·�ɱ�����һ����ѡԴ��ַʱ���Ž�fib_info�ṹ���뵽������С�
	 */	
	struct hlist_node	fib_lhash;
	/**
	 * fib_treeref�ǳ��и�fib_infoʵ�����õ�fib_node���ݽṹ����Ŀ
	 */
	int			fib_treeref;
	/**
	 * fib_clntref������·�ɲ��ҳɹ��������е����ü�����
	 */
	atomic_t		fib_clntref;
	/**
	 * ���·�������ڱ�ɾ���ı�־�����ñ�־������Ϊ1ʱ����������ݽṹ����ɾ����������ʹ�á�
	 */
	int			fib_dead;
	/**
	 * ���ֶ�ΪRTNH_F_XXX��־����ϡ���ǰʹ�õ�Ψһ��־��RTNH_F_DEAD��
	 * ����һ����·��·���������������fib_nh�ṹ��������RTNH_F_DEAD��־ʱ�����øñ�־��
	 */
	unsigned		fib_flags;
	/**
	 * ����·�ɵ�Э�顣��ʾ·��Э���ػ����̡�
	 * fib_protocolȡֵ����RTPROT_STATIC��·��������ں����ɣ������û��ռ�·��Э�����ɣ���
	 */
	int			fib_protocol;
	/**
	 * ��ѡԴIP��ַ��
	 */
	u32			fib_prefsrc;
	/**
	 * ·�����ȼ���ֵԽС�����ȼ�Խ�ߡ�
	 * ����ֵ������IPROUTE2���е�metric/priority/preference�ؼ��������á���û����ȷ�趨ʱ���ں˽�����ֵ��ʼ��Ϊȱʡֵ0��
	 */
	u32			fib_priority;
	/**
	 * ������·��ʱ��ip route�������ָ��һ��metrics��
	 * fib_metrics�Ǵ洢��һ��metrics��һ��������û����ȷ�趨��Metrics�ڳ�ʼ��ʱ������Ϊ0��
	 */
	u32			fib_metrics[RTAX_MAX];
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	/**
	 * ·��������һ���ĸ�����
	 */
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/**
	 * ����ʵ�ּ�Ȩ�����ת�㷨��
	 * ���ֶα���ʼ��Ϊfib_infoʵ����������һ��Ȩֵ��fib_nh->nh_weight�����ܺͣ�������������ĳЩԭ�������ʹ�õ���һ��������RTNH_F_DEAD��־����
	 * ÿ������fib_select_multipath��ѡ��һ����һ��ʱ��fib_power��ֵ�ݼ�������ֵ�ݼ�Ϊ��ʱ�����³�ʼ����
	 */
	int			fib_power;
#endif
	/**
	 * fib_nh�ṹ���飬����Ĵ�СΪfib_info->fib_nhs��
	 */
	struct fib_nh		fib_nh[0];
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

/**
 * ����·�ɱ��ظýṹ��
 * �������ݲ����Ǽ򵥵ذ�����һ����Ϣ�����Ұ������������·�ɵ���������Ҫ�ĸ��������
 */
struct fib_result {
	/**
	 * ƥ��·�ɵ�ǰ׺���ȡ�
	 */
	unsigned char	prefixlen;
	/**
	 * ��·��·�����ɶ����һ��������ġ����ֶα�ʶ�Ѿ���ѡ�е���һ����
	 */
	unsigned char	nh_sel;
	/**
	 * �������ֶα���ʼ��Ϊ��ƥ���fib_aliasʵ����fa_type��fa_scope�ֶε�ȡֵ��
	 */
	unsigned char	type;
	unsigned char	scope;
	/**
	 * ��ƥ���fib_aliasʵ���������fib_infoʵ����
	 */
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/**
	 * ��ǰ���ֶβ�ͬ���ǣ����ֶ���fib_lookup����ʼ����ֻ�е��ں˱���֧�ֲ���·��ʱ�����ֶβŰ�����fib_result���ݽṹ�ڡ�
	 */
	struct fib_rule	*r;
#endif
};


#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

/**
 * ��Щ���һ��������fib_result�ṹ����ȡ�ض����ֶΣ�����FIB_RES_DEV��ȡ��nh_dev�ֶΡ�
 */
#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

/**
 * ��ʾһ��·�ɱ���Ҫ������·�ɱ��������
 * ����ṹ��Ҫ��һ��·�ɱ��ʶ�͹����·�ɱ��һ�麯��ָ�����
 */
struct fib_table {
	/**
	 * ·�ɱ��ʶ����include/linux/rtnetlink.h�ļ��п����ҵ�Ԥ�ȶ��������Ϊrt_class_t��ֵ������RT_TABLE_LOCAL��
	 */
	unsigned char	tb_id;
	/**
	 * δ��ʹ�á�
	 */
	unsigned	tb_stamp;
	/**
	 * ���������fib_lookup������á�����·�ɲ��ҡ���ʼ��Ϊfn_hash_lookup��
	 */
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	/**
	 * tb_insert��inet_rtm_newroute��ip_rt_ioctl���ã������û��ռ��ip route add/change/replace/prepend/append/test ����� route add ���
	 * Ҳ��fib_magic���á�
	 */
	int		(*tb_insert)(struct fib_table *table, struct rtmsg *r,
				     struct kern_rta *rta, struct nlmsghdr *n,
				     struct netlink_skb_parms *req);
	/**
	 * ���Ƶأ�tb_delete��inet_rtm_delroute����ip route del ... ������������Ӧ����ip_rt_ioctl����route del ... ������������Ӧ�����ã����ڴ�·�ɱ���ɾ��һ��·�ɡ�
	 * Ҳ��fib_magic���á�
	 */
	int		(*tb_delete)(struct fib_table *table, struct rtmsg *r,
				     struct kern_rta *rta, struct nlmsghdr *n,
				     struct netlink_skb_parms *req);
	/**
	 * Dump��·�ɱ�����ݡ��ڴ�������"ip route get..."���û�����ʱ�����
	 */
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/**
	 * ��������RTNH_F_DEAD��־��fib_info�ṹɾ�������������ա�
	 */
	int		(*tb_flush)(struct fib_table *table);
	/**
	 * ѡ��һ��ȱʡ·�ɡ�
	 */
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	/**
	 * ����һ��fn_hash�ṹ����33��·�ɱ�
	 * ָ��ýṹ��β��������fib_table�ṹ����һ������ṹ��һ����ʱ�����������Ǻ����õģ���Ϊ�����ڸýṹ����ʱ������ָ����һ�����ݽṹ
	 */
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(int id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

/**
 * ���������������ʼ��һ����·�ɱ����������ӵ�fib_tables�����ڡ�
 */
static inline struct fib_table *fib_new_table(int id)
{
	return fib_get_table(id);
}

/**
 * ����·�ɱ�Ĳ��ҡ�
 */
static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * ����֧�ֲ���·��ʱ��ֱ�ӵ��ñ���·�ɺ���·�ɵ�����������
	 * IPV4������������fn_hash_lookup��
	 */
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

/**
 * ����ת��������û�е���Ŀ�ĵص�·�ɱ���ʱѡ��һ��ȱʡ·�ɡ���������������������ʱ����ip_route_output_slow�������
 *		fib_lookup���ص�·������������Ϊ/0��res.prefixlenΪ0��
 *		fib_lookup���ص�·���������ΪRTN_UNICAST
 * fib_select_default�����ڶ�����õ�ȱʡ·�������������ѡ��
 */
static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	/**
	 * ��res·�������һ�����ص�scopeΪRT_SCOPE_LINKʱ��fib_select_default�Ų���ip_fib_main_table��
	 * ������Ϊ���ر�����L2����ֱ��ķ�Χ���С�
	 */
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		/**
		 * tb_select_default����ʼ��Ϊfn_hash_select_default
		 */
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
#define ip_fib_local_table (fib_tables[RT_TABLE_LOCAL])
#define ip_fib_main_table (fib_tables[RT_TABLE_MAIN])

extern struct fib_table * fib_tables[RT_TABLE_MAX+1];
extern int fib_lookup(const struct flowi *flp, struct fib_result *res);
extern struct fib_table *__fib_new_table(int id);
extern void fib_rule_put(struct fib_rule *r);

/**
 * ����һ��·�ɱ�ID����0��255��һ����ֵ�����ú�����fib_tables���鷵����Ӧ��fib_info�ṹ��
 */
static inline struct fib_table *fib_get_table(int id)
{
	if (id == 0)
		id = RT_TABLE_MAIN;

	return fib_tables[id];
}

/**
 * ���������������ʼ��һ����·�ɱ����������ӵ�fib_tables�����ڡ�
 */
static inline struct fib_table *fib_new_table(int id)
{
	if (id == 0)
		id = RT_TABLE_MAIN;

	return fib_tables[id] ? : __fib_new_table(id);
}

extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern void		ip_fib_init(void);
extern int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_getroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb);
extern int fib_validate_source(u32 src, u32 dst, u8 tos, int oif,
			       struct net_device *dev, u32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(u32 gw, struct net_device *dev);
extern int fib_sync_down(u32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern int fib_convert_rtentry(int cmd, struct nlmsghdr *nl, struct rtmsg *rtm,
			       struct kern_rta *rta, struct rtentry *r);
extern u32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(int id);

#ifdef CONFIG_IP_MULTIPLE_TABLES
/* Exported by fib_rules.c */

extern int inet_rtm_delrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_rules(struct sk_buff *skb, struct netlink_callback *cb);
#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif
extern void fib_rules_init(void);
#endif

/**
 * ���з���·������ʱ����������realms��
 */
static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	/**
	 * ���ں�û��ʹ�ܲ���·��ʱ�����򵥵ؽ�Դ·��realm��Ŀ��·��realm������
	 */
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	/**
	 * ���ں�ʹ�ܲ���·��ʱ���������������Դrealm��ΪĿ��realm��
	 */
	rtag = fib_rules_tclass(res);
	/**
	 * ���Ŀ��·��realm������D1��ΪԴrealm������Ŀ�Ĳ���realm��ΪԴrealm��
	 */
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#endif  /* _NET_FIB_H */
