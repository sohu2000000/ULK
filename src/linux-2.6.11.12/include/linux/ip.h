/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP protocol.
 *
 * Version:	@(#)ip.h	1.0.2	04/28/93
 *
 * Authors:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_IP_H
#define _LINUX_IP_H
#include <asm/byteorder.h>

#define IPTOS_TOS_MASK		0x1E
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_MINCOST		0x02

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00


/* IP options */
#define IPOPT_COPY		0x80
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

/**
 * ����IPѡ�������ֶ��е�number��copied��class����
 */
#define	IPOPT_COPIED(o)		((o)&IPOPT_COPY)
#define	IPOPT_CLASS(o)		((o)&IPOPT_CLASS_MASK)
#define	IPOPT_NUMBER(o)		((o)&IPOPT_NUMBER_MASK)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

/**
 * ��IPѡ��ĳ��Ȳ���4�ֽڵ�������ʱ������IPOPT_ENDѡ�����IPͷ����ʹѡ��4�ֽڶ��롣
 */
#define IPOPT_END	(0 |IPOPT_CONTROL)
/**
 * IPOPT_NOOPѡ������������ѡ��֮�������䡣���磬��������IPѡ������ı߽硣
 */
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

#define IPVERSION	4
#define MAXTTL		255
#define IPDEFTTL	64

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/igmp.h>
#include <net/flow.h>

/**
 * IPѡ�
 */
struct ip_options {
  /**
   * ���ڳ�����˵�����ָ����Դ·�ɣ����ǵ�һ��Դ·�ɡ�
   */
  __u32		faddr;				/* Saved first hop address */
  /**
   * ����ѡ��ĳ��ȡ�����IP��ͷ�Ķ��壬��ֵ���Ϊ40�ֽڡ�
   */
  unsigned char	optlen;
  unsigned char srr;
  /**
   * ��rrΪ��0ʱ��"record route"����IPѡ��֮һ�������ֶε�ֵ�ʹ����ѡ����IP��ͷ����ʼ��ƫ������
   * ���ֶκ�rr_needaddrһ����á�
   */
  unsigned char rr;
  /**
   * ��tsΪ��0ʱ��"timestamp"��IPѡ��֮һ�������ֶε�ֵ�ʹ����ѡ����IP��ͷ����ʼ��ƫ������
   * ���ֶκ�ts_needaddr��ts_needtimeһ����á�
   */
  unsigned char ts;
  /**
   * ���ֶ�ֻ���Ѵ���������壬��ѡ����û��ռ���setsockoptϵͳ���ô���ʱ���ͻ��趨��Ȼ������ǰ��û���õ���
   */
  unsigned char is_setbyuser:1,			/* Set by setsockopt?			*/
  				/**
  				 * �����ؽڵ㴫��һ�����ز����İ�ʱ���Լ������ؽڵ�ظ�һ��ICMP����ʱ��
  				 * ����Щ������ԣ�is_dataΪ�棬��_data��ָ��һ�����򣬴��������Ҫ���ӵ�IP��ͷ��ѡ�
  				 */
                is_data:1,			/* Options in __data, rather than skb	*/
                /**
                 * ���ϸ�·��Ϊѡ��֮һʱ��is_strictroute��־�ͻ��趨��
                 */
                is_strictroute:1,		/* Strict source route			*/
                srr_is_hit:1,			/* Packet destination addr was our one	*/
                /**
                 * ���IP��ͷ�ѱ��޸ģ���IP��ַ��ʱ��������ͻ��趨��
                 * ֪������·ǳ����ô�����Ϊ�����Ҫ��ת�������ֶλ�ָ��IPУ��ͱ������¼��㡣
                 */
                is_changed:1,			/* IP checksum more not valid		*/	
                /**
                 * ��rr_needaddrΪ��ʱ��"record route"��IPѡ��֮һ�����ұ�ͷ�л��пռ��������һ��·����
                 * ��ˣ���ǰ�ڵ�Ӧ�ð�����ӿڵ�IP��ַ������rr��IP��ͷ����ָ��ƫ������
                 */
                rr_needaddr:1,			/* Need to record addr of outgoing dev	*/
                /**
                 * ����ѡ��Ϊ��ʱ��"timestamp"����IPѡ��֮һ�����ұ�ͷ����Ȼ�пռ��������һ��ʱ�����
                 * ��ˣ���ǰ�ڵ�Ӧ�ðѴ���ʱ�����IP��ͷ����λ�þ���ts��ָ����ƫ������
                 */
                ts_needtime:1,			/* Need to record timestamp		*/
                /**
                 * ��ts��ts_needtimeһ��ʹ�ã���ָ�����豸��IP��ַҲӦ�ÿ�����IP��ͷ��
                 */
                ts_needaddr:1;			/* Need to record addr of outgoing dev  */
  /**
   * ����ѡ��Ϊ��ʱ��"route alert"����IPѡ��֮һ��
   */
  unsigned char router_alert;
  /**
   * ��Ϊ��λ�ö���32λ�߽�ʱ���ڴ�Ĵ�ȡ��ȽϿ죬LINUX�ں����ݽṹͨ������������ֶΣ�__padn������䣬�Ա�ʹ��ߴ�Ϊ32�ı����������__pad1��__pad2����;�����˱������á�
   */
  unsigned char __pad1;
  unsigned char __pad2;
  unsigned char __data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct ipv6_pinfo;

/**
 * PF_INET�׿�ʵ������ipv4ר�ô�����ƿ飬�洢ipv4��һЩר�����ԡ�
 * �Ƚ�ͨ�õ�IPv4Э���������飬����TCP\UDP\RAWSOCK�Ĺ��п�����Ϣ��
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	/**
	 * �׿ڵ��������Ϣ
	 */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	/* Ŀ��IP��ַ */
	__u32			daddr;		/* Foreign IPv4 addr */
	/* �Ѿ��󶨵ı���IP��ַ */
	__u32			rcv_saddr;	/* Bound local IPv4 addr */
	/* Ŀ�Ķ˿� */
	__u16			dport;		/* Destination port */
	/* �����ֽ���ı��ض˿ں� */
	__u16			num;		/* Local port */
	/* ����ʱʹ�õĵ�ַ�����Ϊ0����ʾʹ�÷��ͽӿڵĵ�ַ(����˹㲥���ಥ��ַʱ) */
	__u32			saddr;		/* Sending source */
	/* ����TTL */
	int			uc_ttl;		/* Unicast TTL */
	/* �������ñ����ײ���TOS�� */
	int			tos;		/* TOS */
	/* һЩIPPROTO_IP�����ѡ��ֵ����IP_CMSG_PKTINFO */
	unsigned	   	cmsg_flags;
	/**
	 * IP���ݱ�ѡ���ָ�롣
	 */
	struct ip_options	*opt;
	/* �����ֽ���ı��ض˿ں� */
	__u16			sport;		/* Source port */
	/* �Ƿ���Ҫ�Լ�����IP�ײ� */
	unsigned char		hdrincl;	/* Include headers ? */
	/* �鲥TTL */
	__u8			mc_ttl;		/* Multicasting TTL */
	/* �鲥�Ƿ���Ҫ���� */
	__u8			mc_loop;	/* Loopback */
	/* �׽ӿ��Ƿ�֧��PMTU */
	__u8			pmtudisc;
	__u16			id;		/* ID counter for DF pkts */
	/* �Ƿ����������չ�Ŀɿ�������Ϣ */
	unsigned		recverr : 1,
	/* �Ƿ�����󶨷�������ַ�� */
				freebind : 1;
	/* �鲥�豸���� */
	int			mc_index;	/* Multicast device index */
	/* �����鲥���ĵ�Դ��ַ */
	__u32			mc_addr;
	/* �鲥���б� */
	struct ip_mc_socklist	*mc_list;	/* Group array */
	/*
	 * Following members are used to retain the infomation to build
	 * an ip header on each ip fragmentation while the socket is corked.
	 */
	/**
	 * cork�ṹ�����ڴ����׽���CORKѡ�
	 * cork�ṹ��ip_append_data��ip_append_page�а�������Ҫ��ɫ���洢��������������ȷ�����ݷֶ�������ı�����Ϣ���ڸ�����Ϣ�У�������IP��ͷ���ѡ�����еĻ����Լ�Ƭ�γ��ȡ�
	 */
	struct {
		/**
		 * ĿǰIPV4ֻ��һ����־�����趨��IPCORK_OPT�����˱�־�趨ʱ����ζ��opt����ѡ�
		 */
		unsigned int		flags;
		/**
		 * ����������Ƭ�εĳߴ硣�˳ߴ������Ч���ɺ�L3��ͷ������ͨ������PMTU��
		 */
		unsigned int		fragsize;
		/**
		 * Ҫ�õ�IPѡ�
		 */
		struct ip_options	*opt;
		/**
		 * ���ڴ���IP����·�ɱ�����Ŀ��
		 */
		struct rtable		*rt;
		/**
		 * �Ѿ���������зֶε��ܳ������ܳ���64KB��
		 */
		int			length; /* Total length of all frames */
		/**
		 * Ŀ�ĵ�IP��ַ��
		 */
		u32			addr;
		/**
		 * �й��������˵����Ϣ����
		 */
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
/**
 * ��sockǿתΪinet_sock.
 */
static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->slab_obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif
#endif
/**
 * IP��ͷ��
 */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	/**
	 * IPЭ��汾��
	 */
	__u8	version:4,
	/**
	 * Э��ͷ���ȡ����ֵΪ15����4�ֽ�Ϊ��λ����ˣ�IPͷ��󳤶�Ϊ60.
	 * ���ڻ�����ͷ������20�ֽڣ���ˣ�IPѡ�����Ϊ40�ֽڡ�
	 */
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	/**
	 * �������ͣ����ֶε�ֵ�Ѿ����׼Э����������
	 * ����Ϊ��ý�����Э����ʹ�á�
	 */
	__u8	tos;
	/**
	 * ���ĳ��ȣ�������ͷ�ͷ�Ƭ��
	 */
	__u16	tot_len;
	/**
	 * IP��ʶ��LINUXΪÿ��Զ�˵�ַ������һ��ID������
	 */
	__u16	id;
	/**
	 * ��Ƭ��ԭʼ�����е�ƫ�ơ�
	 */
	__u16	frag_off;
	/**
	 * TTL��·������ÿ��ת��ʱ�ݼ���ֵ��
	 */
	__u8	ttl;
	/**
	 * L4��Э���ʶ��
	 */
	__u8	protocol;
	/**
	 * У��͡�
	 */
	__u16	check;
	/**
	 * Դ��ַ��
	 */
	__u32	saddr;
	/**
	 * Ŀ�ĵ�ַ��
	 */
	__u32	daddr;
	/*The options start here. */
};

struct ip_auth_hdr {
	__u8  nexthdr;
	__u8  hdrlen;		/* This one is measured in 32 bit units! */
	__u16 reserved;
	__u32 spi;
	__u32 seq_no;		/* Sequence number */
	__u8  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};

struct ip_comp_hdr {
	__u8 nexthdr;
	__u8 flags;
	__u16 cpi;
};

#endif	/* _LINUX_IP_H */
