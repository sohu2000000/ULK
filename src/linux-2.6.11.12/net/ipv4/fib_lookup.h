#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

/**
 * ����ͬһĿ�����ε�����TOS�Ȳ�����ͬ��·�ɱ�����ͨ��fib_aliasʵ�������ֵġ�
 */
struct fib_alias {
	/**
	 * ����ͬһ��fib_node�ṹ�����������fib_aliasʵ��������һ��
	 */
	struct list_head	fa_list;
	/**
	 * ��ָ��ָ��һ��fib_infoʵ������ʵ���洢����δ������·����ƥ�䱨�ĵ���Ϣ��
	 */
	struct fib_info		*fa_info;
	/**
	 * ·�ɵķ������ͣ�TOS������λ�ֶΡ�
	 * ��ֵΪ��ʱ��ʾ��û������TOS��������·�ɲ���ʱ�κ�ֵ������ƥ�䡣
	 */
	u8			fa_tos;
	/**
	 * ·�����͡�
	 */
	u8			fa_type;
	/**
	 * ·�ɵ�scope��IPv4·�ɴ�����ʹ�õ���Ҫscope��
	 *		RT_SCOPE_NOWHERE:		�Ƿ�scope���������溬����·���ͨ���κεط���������Ͼ���ζ��û�е���Ŀ�ĵص�·�ɡ�
	 *		RT_SCOPE_HOST:			������Χ�ڵ�·�ɡ�scopeΪRT_SCOPE_HOST��·��������ӣ�Ϊ���ؽӿ�����IP��ַʱ�Զ�������·�ɱ��
	 *		RT_SCOPE_LINK:			Ϊ���ؽӿ����õ�ַʱ��������Ŀ�ĵ�Ϊ���������ַ�����������붨�壩�������㲥��ַ��·�ɱ����scope����RT_SCOPE_LINK��
	 *		RT_SCOPE_UNIVERSE:		��scope���������е�ͨ��Զ�̷�ֱ��Ŀ�ĵص�·�ɱ��Ҳ������Ҫһ����һ�����ص�·�����
	 */
	u8			fa_scope;
	/**
	 * һЩ��־�ı���λͼ��ֻʹ����һ����־:FA_S_ACCESSED��
	 */
	u8			fa_state;
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(const struct rtmsg *r,
					struct kern_rta *rta,
					const struct nlmsghdr *,
					int *err);
extern int fib_nh_match(struct rtmsg *r, struct nlmsghdr *,
			struct kern_rta *rta, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u8 tb_id, u8 type, u8 scope, void *dst,
			 int dst_len, u8 tos, struct fib_info *fi);
extern void rtmsg_fib(int event, u32 key, struct fib_alias *fa,
		      int z, int tb_id,
		      struct nlmsghdr *n, struct netlink_skb_parms *req);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int *dflt);

#endif /* _FIB_LOOKUP_H */
