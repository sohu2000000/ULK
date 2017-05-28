/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Interfaces handler.
 *
 * Version:	@(#)dev.h	1.0.10	08/12/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Donald J. Becker, <becker@cesdis.gsfc.nasa.gov>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Bjorn Ekwall. <bj0rn@blox.se>
 *              Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Moved to /usr/include/linux for NET3
 */
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifdef __KERNEL__
#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/config.h>
#include <linux/device.h>
#include <linux/percpu.h>

struct divert_blk;
struct vlan_group;
struct ethtool_ops;

					/* source back-compat hooks */
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )

#define HAVE_ALLOC_NETDEV		/* feature macro: alloc_xxxdev
					   functions are available. */
#define HAVE_FREE_NETDEV		/* free_netdev() */
#define HAVE_NETDEV_PRIV		/* netdev_priv() */

#define NET_XMIT_SUCCESS	0
#define NET_XMIT_DROP		1	/* skb dropped			*/
#define NET_XMIT_CN		2	/* congestion notification	*/
#define NET_XMIT_POLICED	3	/* skb is shot by police	*/
#define NET_XMIT_BYPASS		4	/* packet does not leave via dequeue;
					   (TC use only - dev_queue_xmit
					   returns this as NET_XMIT_SUCCESS) */

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0   /* keep 'em coming, baby */
#define NET_RX_DROP		1  /* packet dropped */
#define NET_RX_CN_LOW		2   /* storm alert, just in case */
#define NET_RX_CN_MOD		3   /* Storm on its way! */
#define NET_RX_CN_HIGH		4   /* The storm is here */
#define NET_RX_BAD		5  /* packet dropped due to kernel error */

#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

#endif

#define MAX_ADDR_LEN	32		/* Largest hardware address length */

/* Driver transmit return codes */
/**
 * ���ͳɹ�����������û�б��ͷš�
 * �������������ͷŻ����������������ں�NET_TX_SOFTIRQ���жϴ����������ṩ�˱�ÿһ�����������ͷŸ���Ч���ڴ洦���ֶΡ�
 */
#define NETDEV_TX_OK 0		/* driver took care of packet */
/**
 * ���������������ͻ����ȱ���㹻�Ŀռ䡣�����������̽�⵽ʱ������ͨ������netif_stop_queue��
 */
#define NETDEV_TX_BUSY 1	/* driver tx path was busy*/
/**
 * ��������ס������������֧��NETIF_F_LLTXʱ���ſ��ܷ����⴦ֵ��
 */
#define NETDEV_TX_LOCKED -1	/* driver tx lock was already taken */

/*
 *	Compute the worst case header length according to the protocols
 *	used.
 */
 
#if !defined(CONFIG_AX25) && !defined(CONFIG_AX25_MODULE) && !defined(CONFIG_TR)
#define LL_MAX_HEADER	32
#else
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
#define LL_MAX_HEADER	96
#else
#define LL_MAX_HEADER	48
#endif
#endif

#if !defined(CONFIG_NET_IPIP) && \
    !defined(CONFIG_IPV6) && !defined(CONFIG_IPV6_MODULE)
#define MAX_HEADER LL_MAX_HEADER
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

/*
 *	Network device statistics. Akin to the 2.0 ether stats but
 *	with byte counters.
 */
/**
 * ���������������豸�����еĳ���ͳ����Ϣ����Щ��Ϣ����ͨ������get_stats����ȡ
 */
struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};


/* Media selection options. */
enum {
        IF_PORT_UNKNOWN = 0,
        IF_PORT_10BASE2,
        IF_PORT_10BASET,
        IF_PORT_AUI,
        IF_PORT_100BASET,
        IF_PORT_100BASETX,
        IF_PORT_100BASEFX
};

#ifdef __KERNEL__

#include <linux/cache.h>
#include <linux/skbuff.h>

struct neighbour;
struct neigh_parms;
struct sk_buff;

/**
 * ����֡��ͳ����Ϣ��
 * һЩ������ͨ��������netif_rx�и��£������ڷ�NAPI������ʹ�ã�������ζ��ʹ��NAPI����ʱ�����ǵ�ֵ����ȷ��
 */
struct netif_rx_stats
{
	/**
	 * �Ѿ������������������������İ������ֵ��netif_rx��netif_recevie_skb�ж�����¡�����ζ���ڲ�ʹ��NAPIʱ��ͬһ��֡��ͳ�������Ρ�
	 */
	unsigned total;
	/**
	 * ��������֡����CPU����throttle״̬ʱ���յ��İ��ᱻ������
	 */
	unsigned dropped;
	/**
	 * ��CPU������л���֡ʱ��net_rx_action���ò����أ��Ա���CPUռ�ù���Ĵ�����
	 */
	unsigned time_squeeze;
	/**
	 * CPU����throttle״̬�Ĵ���������ֵ��netif_rx���ӡ�
	 */
	unsigned throttled;
	/**
	 * Fastroute����ʹ�õ��ֶΡ����������2.6.8���Ѿ��������ˡ�
	 */
	unsigned fastroute_hit;
	unsigned fastroute_success;
	unsigned fastroute_defer;
	unsigned fastroute_deferred_out;
	unsigned fastroute_latency_reduction;
	/**
	 * ���ܻ���豸�������Ĵ��������ܻ��������������һ��CPU�Ѿ��������������������ֵ��qdisc_restart���¡�������֡���ͣ��������ڽ���ʱ����
	 */
	unsigned cpu_collision;
};

DECLARE_PER_CPU(struct netif_rx_stats, netdev_rx_stat);


/*
 *	We tag multicasts with these structures.
 */
 
struct dev_mc_list
{	
	struct dev_mc_list	*next;
	__u8			dmi_addr[MAX_ADDR_LEN];
	unsigned char		dmi_addrlen;
	int			dmi_users;
	int			dmi_gusers;
};

/**
 * ������·��ͷ����Ϣ���ڼӿ촫���ٶȡ�
 * һ�ν�һ�������ͷ����Ϣ���Ƶ����ͻ����бȰ�λ���ͷ����ϢҪ��öࡣ
 * ���������е������豸������֧�ֻ���ͷ����Ϣ��
 */
struct hh_cache
{
	/**
	 * ��ͬһ��neighbour������Ļ����L2֡ͷ�����ж�������ǣ�����һ��hh_typeֵֻ����һ������ھӹ������μ�neigh_hh_init����
	 */
	struct hh_cache *hh_next;	/* Next entry			     */
	/**
	 * ���ü�����
	 */
	atomic_t	hh_refcnt;	/* number of users                   */
	/**
	 * ��L3��ַ��ص�Э�顣
	 */
	unsigned short  hh_type;	/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
    /**
     * ���ֽ�����ʾ�Ļ����֡ͷ���ȡ�
     */
	int		hh_len;		/* length of header */
	/**
	 * ������ĺ�������neigh->outputһ���������������ʼ��Ϊneigh->ops VFT�е�һ��������
	 */
	int		(*hh_output)(struct sk_buff *skb);
	/**
	 * ���ھ��������±���hh_cache�ṹ������
	 */
	rwlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - ((__len) & (HH_DATA_MOD - 1)))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	/**
	 * �����֡ͷ��
	 */
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

/* Reserve HH_DATA_MOD byte aligned hard_header_len, but at least that much.
 * Alternative is:
 *   dev->hard_header_len ? (dev->hard_header_len +
 *                           (HH_DATA_MOD - 1)) & ~(HH_DATA_MOD - 1) : 0
 *
 * We could use other alignment values, but we must maintain the
 * relationship HH alignment <= LL alignment.
 */
#define LL_RESERVED_SPACE(dev) \
	(((dev)->hard_header_len&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+extra)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code.
 */

enum netdev_state_t
{
	/**
	 * �����λΪ1����������֡��
	 */
	__LINK_STATE_XOFF=0,
	/**
	 * �豸ʱ����ģ������־���Ա�netif_running��⡣������������߽�ֹ���Ͱ������ǲ���������߽�ֹ���հ���
	 */
	__LINK_STATE_START,
	/**
	 * �豸�ǿɼ��ģ����״̬�ƺ��Ƕ���ģ������ܹ�ֻ���Ȳ���豸��ʱ�Ƴ���
	 * ��ϵͳ���ڹ���ģʽ�����ʱ�������־�ܹ����ֱ�����ͻָ���
	 * �����־�ܹ���netif_device_present���
	 */
	__LINK_STATE_PRESENT,
	/**
	 * ���豸���ڷ���֡ʱ����λ�����á�
	 */
	__LINK_STATE_SCHED,
	/**
	 * û�д��ݡ��˱�־����netif_carrier_ok���,�Լ�������Ƿ���ͨ��
	 */
	__LINK_STATE_NOCARRIER,
	/**
	 * �ɴ��������Թ����豸����ںͳ�������
	 * �����poll_list�У���˱�־�����á�
	 */
	__LINK_STATE_RX_SCHED,
	__LINK_STATE_LINKWATCH_PENDING
};


/*
 * This structure holds at boot time configured netdevice settings. They
 * are then used in the device probing. 
 */
/**
 * netdev_boot_setup�����Ĵ�������
 */
struct netdev_boot_setup {
	/**
	 * name ���豸��
	 */
	char name[IFNAMSIZ];
	/**
	 * ifmap �� in include/linux/if.h �ж��壬�Ǵ洢�������õ����ݽṹ
	 */
	struct ifmap map;
};
/**
 * ����ʱ���õ��豸�������,��������������LILO: linux ether=5,0x260,eth0 ether=15,0x300,eth1
 */
#define NETDEV_BOOT_SETUP_MAX 8


/*
 *	The DEVICE structure.
 *	Actually, this whole structure is a big mistake.  It mixes I/O
 *	data with strictly "high-level" data, and it has to know about
 *	almost every data structure used in the INET module.
 *
 *	FIXME: cleanup struct net_device such that network protocol info
 *	moves out.
 */
/**
 * net_device�ṹ�����������豸��ص�������Ϣ��
 * ÿһ�������豸����Ӧһ�������Ľṹ��������ʵ�豸��������̫�������������豸������ bonding �� VLAN��
 */
struct net_device
{

	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	/**
	 * �豸���ƣ����磬eth0��
	 */
	char			name[IFNAMSIZ];

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	/**
	 * ���������������豸���ں�ͨ�����õ����ڴ�߽硣
	 * �������豸������ʼ��������ֻ�ܱ��豸�������ʣ��߲�Э�鲻��Ҫ��������ڴ档
	 */
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	/**
	 * ӳ�䵽�豸�ڴ�ռ���I/O�ڴ���ʼ��ַ��
	 */
	unsigned long		base_addr;	/* device I/O address	*/
	/**
	 * �豸�жϺš������Ա�����豸�����豸��������request_irq���������ֵ��������free_irq���ͷ�����
	 */
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */
	/**
	 * �ӿڵĶ˿����͡�
	 */
	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	/**
	 * �豸��ʹ�õ�DMAͨ����
	 */
	unsigned char		dma;		/* DMA channel		*/

	/**
	 * ����һ�鱻���������ϵͳʹ�õı��
	 */
	unsigned long		state;
	/**
	 * ָ��ȫ�������е���һ���ڵ�
	 */
	struct net_device	*next;
	
	/* The device initialization function. Called only once. */
	/**
	 * ���ڳ�ʼ������������٣����ú�ֹͣһ���豸����Щ����������ÿ���豸�����õ���
	 */
	int			(*init)(struct net_device *dev);

	/* ------- Fields preinitialized in Space.c finish here ------- */

	/**
	 * ������������ں����ж�ʹ��
	 * ÿ��CPU�϶���һ�������͵ĳ��豸���У�ͨ����ָ�룬�����豸������һ��
	 */
	struct net_device	*next_sched;

	/* Interface index. Unique device identifier	*/
	/**
	 * ȫ��Ψһ���豸ID����ÿ���豸ע��ʱ������dev_new_index���ɡ�
	 */
	int			ifindex;
	/**
	 * ���������Ҫ�������⣩����豸ʹ�ã����ڱ�ʶ�������ʵ�豸��
	 */
	int			iflink;


	/**
	 * ��Щ�豸ͳ����Ϣ����ͨ���û��ռ������ʾ������ifconfig��ip��
	 * ������ͳ����Ϣֻ�ܱ��ں�ʹ�á��������������ڻ�ȡ�豸ͳ����Ϣ��
	 * get_stats���ڲ���һ����ͨ�豸����get_wireless_stats���ڲ���һ�������豸��
	 */
	struct net_device_stats* (*get_stats)(struct net_device *dev);
	struct iw_statistics*	(*get_wireless_stats)(struct net_device *dev);

	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	/**
	 * �������豸ʹ�á�
	 */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;

	/**
	 * ���û��ȡ��ͬ�豸������һ�麯��ָ��
	 */
	struct ethtool_ops *ethtool_ops;

	/*
	 * This marks the end of the "visible" part of the structure. All
	 * fields hereafter are internal to the system, and may change at
	 * will (read: may be cleaned up at will).
	 */

	/* These may be needed for future network-power-down code. */
	/**
	 * ���һ��֡��ʼ���͵�ʱ�䣨��jiffies���������豸�����ڷ���֮ǰ�������������
	 * �������������������Ƿ��ڸ�����ʱ���ڰ�֡�����˳�ȥ��
	 * ̫���ķ���ʱ����ζ���д�����������������£��豸����������������
	 */
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/
	/**
	 * ���յ����һ������ʱ�䣨��jiffies��������
	 * Ŀǰ���������û��ʲô�������;�����ǣ������п��ܻ��õ���
	 */
	unsigned long		last_rx;	/* Time of last Rx	*/

	/**
	 * flags�����е�ĳЩλ��ʾ�����豸��֧�ֵĹ��ܣ������Ƿ�֧�ֶಥIFF_MULTICAST �ȣ���
	 * ����λ��ʾ�豸״̬�ı仯������ IFF_UP ����IFF_RUNNING��
	 * �豸����ͨ�����豸��ʼ��ʱ�����豸��֧�ֵĹ��ܣ����豸״̬�����ں˸���ĳЩ�ⲿ�¼�������
	 */
	unsigned short		flags;	/* interface flags (a la BSD)	*/
	/**
	 * gflags�������ᱻʹ�ã�������ֻ��Ϊ�˱��ּ��ݡ�
	 */
	unsigned short		gflags;
	/**
	 * priv_flags�洢һЩ���û��ռ���򲻿ɼ��ı�ǡ�Ŀǰ�����������VLAN���������豸ʹ�á�
	 */
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
        unsigned short          unused_alignment_fixer; /* Because we need priv_flags,
                                                         * and we want to be 32-bit aligned.
                                                         */
	/**
	 * ����䵥Ԫ������ʾ�豸���Դ���֡����󳤶�
	 */
	unsigned		mtu;	/* interface MTU value		*/
	/**
	 * �豸���ͣ���̫����֡�м̵ȣ���
	 */
	unsigned short		type;	/* interface hardware type	*/
	/**
	 * ���ֽ�Ϊ��λ��֡ͷ�����ȡ����磬��̫��֡��ͷ��14�ֽڡ�
	 */
	unsigned short		hard_header_len;	/* hardware hdr length	*/
	/**
	 * ��ͬ��������˽�����ݽṹ.
	 */
	void			*priv;	/* pointer to private data	*/

	/**
	 * ��ЩЭ���������豸��ϵ�һ����һ���豸ʹ�á�
	 * ��ЩЭ����� EQL����������ĸ��ؾ��⣩��Bonding���ֱ�����EtherChannel��trunking������TEQL��true equalizer����������������ϵͳ�е�һ���ŶӲ��ԣ���
	 * ���豸���У���һ���豸��ѡ�����������豸��������������á����������һ��ָ���������豸��ָ�롣
	 * ����豸����һ����ĳ�Ա�����ָ�뱻��ΪNULL�� 
	 */
	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	/**
	 * ��·��㲥��ַ��
	 */
	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/
	/**
	 * dev_addr���豸����·���ַ����Ҫ������IP��ַ����L3��ַ�����ˡ�
	 */
	unsigned char		dev_addr[MAX_ADDR_LEN];	/* hw address	*/
	/**
	 * ��·���ַ�ĳ�����addr_len�����ֽ�Ϊ��λ��
	 * addr_len�Ĵ�С���豸�����йء���̫����ַ�ĳ�����8��
	 */
	unsigned char		addr_len;	/* hardware address length	*/
	/**
	 * IPV6��ʹ�� zSeries  OSA ����ʱ�õ����������
	 * ���������������ͬһ�豸�Ĳ�ͬ����ʵ�壬��Щ����ʵ������ڲ�ͬ���������ϵͳ�й���
	 */
	unsigned short          dev_id;		/* for shared network cards */

	/**
	 * �豸�����Ķಥ��ַ��.��Ӻ�ɾ���ಥ��ַ���Էֱ���ú��� dev_mc_add ��dev_mc_delete���
	 */
	struct dev_mc_list	*mc_list;	/* Multicast mac addresses	*/
	/**
	 * �豸�ಥ��ַ����������ͬ����ʾmc_list��ָ������ĳ��ȡ�
	 */
	int			mc_count;	/* Number of installed mcasts	*/
	/**
	 * "����ģʽ"������
	 */
	int			promiscuity;
	/**
	 * ����Ƿ���ֵ����ô�豸���������еĶಥ��ַ��
	 * �� promiscuity һ�������������һ������������������һ������ֵ��
	 * ������Ϊ����豸������VLAN��bonding�豸�����ܶ�����Ҫ��������е�ַ��
	 * ������������ֵ��0��Ϊ���㣬�ں˻���ú���dev_set_allmulti֪ͨ�豸�������еĶಥ��ַ��
	 * ������ֵ��Ϊ0����ֹͣ�������еĶಥ��ַ��
	 */
	int			allmulti;

	/**
	 * ����ʵ��"Watchdog timer"�����Ź�ʱ�ӵ�ʱ�䡣
	 * ���ǵȴ���ʱ���ܼơ����豸���������ʼ�������������ó�0ʱ��watchdog_timerû��������
	 */
	int			watchdog_timeo;
	/**
	 * ���Ź�ʱ�ӡ�
	 */
	struct timer_list	watchdog_timer;

	/* Protocol specific pointers */
	/**
	 * ����������ָ���ض�Э������ݽṹ��ÿ�����ݽṹ������Э��˽�еĲ�����
	 * ���磬ip_ptrָ��һ�� in_device ���͵Ľṹ������ ip_ptr �������� void*���������� IPv4��صĲ��������а����豸��IP ��ַ�б�ȡ�
	 */
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	*/  
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data */

	/**
	 * ��Щ������NAPIʹ�á�
	 * �������������֡���豸�б��б�ͷ��softnet_data->poll_list��
	 * ������б��е��豸���жϱ���ֹ�������ں�������ѯ���ǡ�
	 */
	struct list_head	poll_list;	/* Link to poll list	*/
	/**
	 * quota��һ����������ʾ��һ�δ�������У�poll�������Ӷ�����ȡ�����ٸ���������
	 * ����ֵÿ����weightΪ��λ���ӣ��������ڲ�ͬ���豸����й�ƽ�����򡣵͵������ζ�Ÿ������ӳ٣���������豸�����ķ��ո�С��
	 * ����NAPI��ص��豸��Ĭ��ֵ���豸ѡ�񡣴��������£���ֵΪ64,����Ҳ��ʹ��16��32�ġ���ֵ����ͨ��sysfs������
	 */
	int			quota;
	int			weight;

	/**
	 * ��Щ���������������������豸�Ľ��գ����Ͷ��У����ҿ��Ա���ͬ��cpu���ʡ�
	 */
	struct Qdisc		*qdisc;
	struct Qdisc		*qdisc_sleeping;
	struct Qdisc		*qdisc_ingress;
	struct list_head	qdisc_list;
	/**
	 * �豸���Ͷ��еĳ��ȡ�
	 * ����ں��а���������������ϵͳ�������������û��ʲô�ã�ֻ�м����ŶӲ��Ի�ʹ��������
	 * ���ֵ����ͨ��sysfs�ļ�ϵͳ�޸ģ���/sys/class/net/device_name/Ŀ¼�£���
	 */
	unsigned long		tx_queue_len;	/* Max frames per queue allowed */

	/* ingress path synchronizer */
	/**
	 * ����������ϵͳ���ڱ��Ⲣ�����ʽ��ն��С�
	 */
	spinlock_t		ingress_lock;
	/* hard_start_xmit synchronizer */
	/**
	 * xmit_lock�������л����豸��������hard_start_xmit�ĵ��á�
	 * ����ζ�ţ�ÿ��cpuÿ��ֻ�ܵ����豸���һ�η��͡�
	 */
	spinlock_t		xmit_lock;
	/* cpu id of processor entered to hard_start_xmit or -1,
	   if nobody entered there.
	 */
	/**
	 * xmit_lock_owner ��ӵ������ CPU �� ID��
	 * �ڵ�cpuϵͳ�ϣ����ֵ�� 0��
	 * �ڶ� cpu ϵͳ�У������û�б�ռ�ã����ֵ��-1��
	 * �ں�ͬ�����������ķ��ͣ�ǰ���������豸��������֧��������ܡ�
	 */
	int			xmit_lock_owner;
	/* device queue lock */
	/**
	 * ����������ϵͳΪÿ�������豸������һ��˽�еķ��Ͷ��С�
	 * queue_lock���ڱ��Ⲣ���ķ��ʡ�
	 */
	spinlock_t		queue_lock;
	/* Number of references to this device */
	/**
	 * ���ü��������������Ϊ0���豸�Ͳ��ܱ�ж��.
	 */
	atomic_t		refcnt;
	/* delayed register/unregister */
	/**
	 * ע���ж��һ�������豸��Ҫ�������裬todo_list�ڵڶ���������ʹ��
	 */
	struct list_head	todo_list;
	/* device name hash chain */
	/**
	 * ��net_device�ṹ���ӵ����ƹ�ϣ���С�
	 */
	struct hlist_node	name_hlist;
	/* device index hash chain */
	/**
	 * ��net_device�ṹ���ӵ�������ϣ���С�
	 */
	struct hlist_node	index_hlist;

	/* register/unregister state machine */
	/**
	 * �豸��ע��״̬��
	 */
	enum { 
		   /**
		    * ����Ϊ0����net_device���ݽṹ�����䣬���ҳ�ʼ��ʱ��dev->reg_state������ֵ��������0��
		    */
		   NETREG_UNINITIALIZED=0,
		   /**
		    * net_device�ṹ������"net_device�ṹ��֯"һ�ڽ��ܵĽṹ�������ں���Ȼ��/sys�ļ�ϵͳ�м���һ����ڡ�
		    */
	       NETREG_REGISTERING,	/* called register_netdevice */
	       /**
	        * �豸����ȫע��
	        */
	       NETREG_REGISTERED,	/* completed register todo */
	       /**
	        * net_device�ṹ�ӽṹ�������Ƴ�
	        */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       /**
	        * �豸��ȫע��(�����Ƴ�/sys�ļ�ϵͳ���)����net_device�ṹ��δ���ͷ� 
	        */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       /**
	        * ���ж�net_device �ṹ�����ö����ͷţ����ݽṹ�༴�ͷţ����ǣ����������ĽǶ�����������sysfs�������ο�"���ü���"
	        */
	       NETREG_RELEASED,		/* called free_netdev */
	} reg_state;

	/* Net device features */
	/**
	 * ��ʾ�豸��֧�ֵĹ��ܵı�����
	 * features������CPU�����豸��֧�ֵĹ���.
	 * �����豸�Ƿ�֧�ָ߶��ڴ�� DMA���Ƿ�֧����Ӳ���������У��͵ȡ�
	 */
	int			features;
#define NETIF_F_SG		1	/* Scatter/gather IO. */
/**
 * ���豸������Ӳ���м���L4У��ͣ�����ֻ���ʹ��Ipv4��TCP��UDP��
 */
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
/**
 * ���豸�ܿɿ�������Ҫʹ���κ�L4У��͡����磬�����豸�Ϳ����˴˹��ܡ�
 */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
/**
 * ���豸����Ϊ�κ�Э����Ӳ���м���L4У��͡���NETIF_F_IP_CSUM��ȣ��˹��ܽ��ټ���
 */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
/**
 * �豸�Ƿ�֧�ַ�ɢ/�ۼ�IO���ܡ�
 */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_TSO		2048	/* Can offload TCP/IP segmentation */
/**
 * �Ƿ��������Լ�ʵ�ַ�������
 */
#define NETIF_F_LLTX		4096	/* LockLess TX */

	/* Called after device is detached from network. */
	/**
	 * ���ڳ�ʼ������������٣����ú�ֹͣһ���豸����Щ����������ÿ���豸�����õ���
	 */
	void			(*uninit)(struct net_device *dev);
	/* Called after last user reference disappears. */
	void			(*destructor)(struct net_device *dev);

	/* Pointers to interface service routines.	*/
	int			(*open)(struct net_device *dev);
	int			(*stop)(struct net_device *dev);
	/**
	 * ����һ��֡��
	 */
	int			(*hard_start_xmit) (struct sk_buff *skb,
						    struct net_device *dev);
#define HAVE_NETDEV_POLL
	/**
	 * ����NAPI��һ���麯�������ڴ��������ȡ������������ÿ���豸��˵���������˽�еġ�
	 */
	int			(*poll) (struct net_device *dev, int *quota);
	/**
	 * ��Щ�������ھӲ�ʹ�á����ֶ����L2֡ͷ������L2֡ͷ���塣
	 */
	int			(*hard_header) (struct sk_buff *skb,
						struct net_device *dev,
						unsigned short type,
						void *daddr,
						void *saddr,
						unsigned len);
	/**
	 * ��Щ�������ھӲ�ʹ�á�
	 * �ú���ֻ��Ϊ�˼���2.2����ǰ���ں��豸��������ʹ������������豸����ʹ��hst_entry->neigh�еĻ�����Ѿ������ĵ�ַ��
	 */	
	int			(*rebuild_header)(struct sk_buff *skb);
#define HAVE_MULTICAST			
	/**
	 * mc_list �� mc_count ����ά�� L2 �Ķಥ��ַ��
	 * ����������������豸����������Щ�ಥ��ַ��
	 * ͨ������£������ᱻֱ�ӵ��ã�����ͨ��һ����װ���������� dev_mc_upload ���߲������汾__dev_mc_upload���á�
	 * ���һ���豸����ά��һ���ಥ��ַ����ô���Լ򵥵��������������еĶಥ��ַ��
	 */
	void			(*set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR  		 
	/**
	 * �޸��豸�� MAC ��ַ������豸���ṩ������ܣ����������豸�������԰����ָ������ΪNULL��
	 */
	int			(*set_mac_address)(struct net_device *dev,
						   void *addr);
#define HAVE_PRIVATE_IOCTL
	/**
	 * ioctlϵͳ�����������豸����������������ioctl��������ĳЩ����
	 */
	int			(*do_ioctl)(struct net_device *dev,
					    struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	/**
	 * �����豸����������irq��io_addr����if_port�ȡ�
	 * �߲����������Э���ַ����do_ioctl���á�
	 * ֻ�к��ٵ��豸ʹ������������µ��豸һ�㶼�����Զ�̽��ķ�ʽ��ȡ��Щ������
	 */
	int			(*set_config)(struct net_device *dev,
					      struct ifmap *map);
#define HAVE_HEADER_CACHE
	/**
	 * ��Щ�������ھӲ�ʹ�á���һ��L2֡ͷ������hh_cache�ṹ�С�
	 */
	int			(*hard_header_cache)(struct neighbour *neigh,
						     struct hh_cache *hh);
	/**
	 * ��Щ�������ھӲ�ʹ�á�
	 * ����һ�����ڵ�hh_cache�������һ���µ�֡ͷ�滻�����л����֡ͷ��
	 * ͨ����neigh_update_hhs�е������������Neigh_updateʹ��neigh_update_hhs���ھ�����и��¡�
	 */
	void			(*header_cache_update)(struct hh_cache *hh,
						       struct net_device *dev,
						       unsigned char *  haddr);
#define HAVE_CHANGE_MTU
	/**
	 * �޸��豸��MTU���޸�mtu������豸�������κ�Ӱ�죬��ֻ����Э��ջ������Ը����µ�mtu��ȷ�ش����Ƭ��
	 */
	int			(*change_mtu)(struct net_device *dev, int new_mtu);

#define HAVE_TX_TIMEOUT
	/**
	 * ��watchdog��ʱ����ʱ��������������������ȷ������һ��֡��ʱ���Ƿ�̫����
	 * ����������û�ж��壬watchdog��ʱ���Ͳ��ᱻ���á�
	 * ��ʱ�ӵ���ʱ���ں˴�����dev_watchdog����tx_timeoutָ��ĺ���������ͨ����������������ͨ��netif_wake_queue�����ӿڵ��ȡ�
	 */
	void			(*tx_timeout) (struct net_device *dev);

	/**
	 * ����������ָ�뱻 VLAN �豸����ע���豸���Դ����VLAN ��ǣ��μ�net/8021q/vlan.c�������������豸����һ��VLAN���ߴ��豸��ɾ��һ��VLAN��
	 */
	void			(*vlan_rx_register)(struct net_device *dev,
						    struct vlan_group *grp);
	void			(*vlan_rx_add_vid)(struct net_device *dev,
						   unsigned short vid);
	void			(*vlan_rx_kill_vid)(struct net_device *dev,
						    unsigned short vid);
	/**
	 * ��Щ�������ھӲ�ʹ�á�
	 * ��һ����������ȡ��ԴL2��ַ��Ȼ�󷵻ظõ�ַ�ĳ��ȡ�
	 */
	int			(*hard_header_parse)(struct sk_buff *skb,
						     unsigned char *haddr);
	/**
	 * ��Щ�������ھӲ�ʹ�á�
	 */	
	int			(*neigh_setup)(struct net_device *dev, struct neigh_parms *);
	/**
	 * ����������ڲ���һ���豸�Ƿ�֧�ֿ��ٽ������ܡ��Ѿ�������
	 */
	int			(*accept_fastpath)(struct net_device *, struct dst_entry*);
#ifdef CONFIG_NETPOLL
	/**
	 * ��Netpollʹ��
	 */
	int			netpoll_rx;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*poll_controller)(struct net_device *dev);
#endif

	/* bridge stuff */
	/**
	 * �豸�����ó����Žӿ�ʱ����Ҫ�ĸ�����Ϣ��
	 */
	struct net_bridge_port	*br_port;

#ifdef CONFIG_NET_DIVERT
	/* this will get initialized at each interface type init routine */
	/**
	 * Diverter���������޸Ľ������Դ��ַ��Ŀ�ĵ�ַ��
	 * �����԰��ض���ת����ĳ���ض��ӿڻ�������Ϊ��ʹ��������ܣ��ں˱����������һЩ���ܣ��������š�
	 * ���ָ��ָ������ݽṹ�а��������������ʹ�õı�������Ӧ���ں�ѡ����"Device drivers ->Networking support ->Networking options ->Frame Diverter"��
	 */
	struct divert_blk	*divert;
#endif /* CONFIG_NET_DIVERT */

	/* class/net/name entry */
	/**
	 * ���µ��ں������ܹ�ʹ�á�����/sys/class/net/name
	 */
	struct class_device	class_dev;
	/* how much padding had been added by alloc_netdev() */
	int padded;
};

#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)

/**
 * �����豸�ṹ��priv
 */
static inline void *netdev_priv(struct net_device *dev)
{
	return (char *)dev + ((sizeof(struct net_device)
					+ NETDEV_ALIGN_CONST)
				& ~NETDEV_ALIGN_CONST);
}

#define SET_MODULE_OWNER(dev) do { } while (0)
/* Set the sysfs physical device reference for the network logical device
 * if set prior to registration will cause a symlink during initialization.
 */
#define SET_NETDEV_DEV(net, pdev)	((net)->class_dev.dev = (pdev))

/**
 * ������Э��
 */
struct packet_type {
	/**
	 * Э�����͡���IPV4��IPV6��ETH_P_ALL
	 */
	unsigned short		type;	/* This is really htons(ether_type).	*/
	/**
	 * ָ�򼤻��Э����豸����eth0��NULL��ʾ�����豸��
	 * �����������������ʹ�ò�ͬ���豸�����в�ͬ�Ĵ�����������Ϊ�ض����豸����һ����������
	 */
	struct net_device		*dev;	/* NULL is wildcarded here		*/
	/**
	 * ����Ҫ��skb->protocol_type����һ��֡ʱ����netif_receive_skb���õĴ���������ip_rcv����
	 */
	int			(*func) (struct sk_buff *, struct net_device *,
					 struct packet_type *);
	/**
	 * ����PF_SOCKET���͵�socket����ָ����ص�sock���ݽṹ��
	 */
	void			*af_packet_priv;
	/**
	 * ���ڽ����ݽṹ���ӵ������С�
	 */
	struct list_head	list;
};

#include <linux/interrupt.h>
#include <linux/notifier.h>

extern struct net_device		loopback_dev;		/* The loopback */
extern struct net_device		*dev_base;		/* All devices */
/**
 * ��dev_base����������ϣ���е����е�����������dev_base_lock������
 */
extern rwlock_t				dev_base_lock;		/* Device list lock */

extern int 			netdev_boot_setup_check(struct net_device *dev);
extern unsigned long		netdev_boot_base(const char *prefix, int unit);
extern struct net_device    *dev_getbyhwaddr(unsigned short type, char *hwaddr);
extern struct net_device *dev_getfirstbyhwtype(unsigned short type);
extern void		dev_add_pack(struct packet_type *pt);
extern void		dev_remove_pack(struct packet_type *pt);
extern void		__dev_remove_pack(struct packet_type *pt);

extern struct net_device	*dev_get_by_flags(unsigned short flags,
						  unsigned short mask);
extern struct net_device	*dev_get_by_name(const char *name);
extern struct net_device	*__dev_get_by_name(const char *name);
extern int		dev_alloc_name(struct net_device *dev, const char *name);
extern int		dev_open(struct net_device *dev);
extern int		dev_close(struct net_device *dev);
extern int		dev_queue_xmit(struct sk_buff *skb);
extern int		register_netdevice(struct net_device *dev);
extern int		unregister_netdevice(struct net_device *dev);
extern void		free_netdev(struct net_device *dev);
extern void		synchronize_net(void);
extern int 		register_netdevice_notifier(struct notifier_block *nb);
extern int		unregister_netdevice_notifier(struct notifier_block *nb);
extern int		call_netdevice_notifiers(unsigned long val, void *v);
extern struct net_device	*dev_get_by_index(int ifindex);
extern struct net_device	*__dev_get_by_index(int ifindex);
extern int		dev_restart(struct net_device *dev);
#ifdef CONFIG_NETPOLL_TRAP
extern int		netpoll_trap(void);
#endif

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
extern int		register_gifconf(unsigned int family, gifconf_func_t * gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

/*
 * Incoming packets are placed on per-cpu queues so that
 * no locking is needed.
 */

struct softnet_data
{
	/**
	 * throttle��avg_blog��cng_level�������ֲ���������ӵ�������㷨
	 * throttle����Ϊ��������������CPU�ǳ���ʱ����ֵΪtrue������Ϊfalse��
	 * ����ֵ������input_pkt_queue����������throttle������ʱ����ǰCPU�ϵ���������������������ܶ�����֡��������
	 */
	int			throttle;
	/**
	 * ��ʾӵ������
	 * Ĭ�ϵģ�avg_blog��cng_level�ڴ���ÿһ֡ʱ���¼��㡣���ǿ��Ա��ݻ������ҹҵ�ʱ���ϣ��Ա�������̫�ฺ�ء�
	 */
	int			cng_level;
	/**
	 * ��ʾinput_pkt_queue���е�ƽ�����ȡ����ķ�Χ��0����󳤶�֮�䣨netdev_max_backlog����avg_blog����������cng_level��
	 * avg_blog��cng_level��CPU��������˱����ڷ�NAPI������
	 */
	int			avg_blog;
	/**
	 * ���������net_dev_init�г�ʼ������֡��û�б���������ǰ���洢�����
	 * ������NAPI����ʹ�á�NAPIʹ�����Լ�˽�еĶ��С�
	 */
	struct sk_buff_head	input_pkt_queue;
	/**
	 * ���ǵȴ�������֡��˫���豸����
	 */
	struct list_head	poll_list;
	/**
	 * output_queue����Ҫ�������豸�б�
	 */
	struct net_device	*output_queue;
	/**
	 * completion_queue���Ѿ��ɹ����ͣ���������ͷŵĻ�������
	 */
	struct sk_buff		*completion_queue;

	/**
	 * ����ȫ��һ��Ƕ������ݽṹ������Ϊnet_device����ʾ��CPU��صĵ��豸��
	 * ����ֶα���NAPI����ʹ�á��豸����Ϊ"backlog device"��
	 */
	struct net_device	backlog_dev;	/* Sorry. 8) */
};

DECLARE_PER_CPU(struct softnet_data,softnet_data);

#define HAVE_NETIF_QUEUE
/**
 * �����豸������
 */
static inline void __netif_schedule(struct net_device *dev)
{
	/**
	 * ����豸�Ѿ������ȷ��ͣ������κ����顣
	 */
	if (!test_and_set_bit(__LINK_STATE_SCHED, &dev->state)) {
		unsigned long flags;
		struct softnet_data *sd;

		/**
		 * ����__netif_schedule�������ж��������ڻ������ж�������֮�ⱻ���ã������������豸��output_queue����ʱ����ֹ�жϡ�
		 */
		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		/**
		 * ����豸��output_queue����ͷ�����������poll_list���ơ�
		 * ÿ��CPU����һ��output_queue������ÿ��CPU����һ��poll_listһ����
		 * ������NAPI���Ƿ�NAPI����ʹ��output_queue����poll_list������NAPI�豸ʹ�á�
		 * output_list�����е��豸��net_device->next_schedָ��������һ��
		 */
		dev->next_sched = sd->output_queue;
		sd->output_queue = dev;
		/**
		 * ����ִ��NET_TX_SOFTIRQ���жϡ�__LINK_STATE_SCHED��������ʾ�豸��output_queue�����У���ʾ��һЩ����Ҫ�����͡�
		 * ����__LINK_STATE_RX_SCHED���ơ�ע�⣺����豸�Ѿ������ȣ���ô__netif_schedule�����κ����顣
		 */
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

/**
 * �����豸������ʱ���ŵ����豸��
 */
static inline void netif_schedule(struct net_device *dev)
{
	if (!test_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

/**
 * �����豸����֡��ͨ�������豸��������������豸ʱ��������
 */
static inline void netif_start_queue(struct net_device *dev)
{
	clear_bit(__LINK_STATE_XOFF, &dev->state);
}

/**
 * ����豸����ֹ���ͣ���ʹ���豸���͡�ͬʱ�����豸��ʼ���͡�
 * �������豸���б���ֹ�ڼ䣬�����еط����Է��Ͱ�����˵������б�Ҫ�ġ�
 */
static inline void netif_wake_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	if (test_and_clear_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

/**
 * ��ֹ�豸����֡���κ����豸�ϳ��Խ��з��͵Ĳ�����������ֹ��
 */
static inline void netif_stop_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	set_bit(__LINK_STATE_XOFF, &dev->state);
}

/**
 * ���س����е�״̬��������߽�ֹ��
 */
static inline int netif_queue_stopped(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}


/* Use this variant when it is known for sure that it
 * is executing from interrupt context.
 */
/**
 * ���ж������ģ��ͷ�sk_buff�ĺ�����
 * ���򵥵Ľ�����������completion_queue���У�Ȼ�������ж����ͷš��������Լӿ��жϵĴ���
 */
static inline void dev_kfree_skb_irq(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users)) {
		struct softnet_data *sd;
		unsigned long flags;

		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		skb->next = sd->completion_queue;
		sd->completion_queue = skb;
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

/* Use this variant in places where it could be invoked
 * either from interrupt or non-interrupt context.
 */
/**
 * �ڲ�ͬ�����������ͷŻ����������ж��������л������ж��������⡣
 */
static inline void dev_kfree_skb_any(struct sk_buff *skb)
{
	if (in_irq() || irqs_disabled())/* ������ж������Ļ��߹��ж�״̬�£����򵥵Ľ����ͷŰ��ŵ������У�Ȼ�������ж��������ͷš� */
		dev_kfree_skb_irq(skb);
	else
		dev_kfree_skb(skb);
}

#define HAVE_NETIF_RX 1
extern int		netif_rx(struct sk_buff *skb);
extern int		netif_rx_ni(struct sk_buff *skb);
#define HAVE_NETIF_RECEIVE_SKB 1
extern int		netif_receive_skb(struct sk_buff *skb);
extern int		dev_ioctl(unsigned int cmd, void __user *);
extern int		dev_ethtool(struct ifreq *);
extern unsigned		dev_get_flags(const struct net_device *);
extern int		dev_change_flags(struct net_device *, unsigned);
extern int		dev_change_name(struct net_device *, char *);
extern int		dev_set_mtu(struct net_device *, int);
extern void		dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev);

extern void		dev_init(void);

extern int		netdev_nit;

/* Called by rtnetlink.c:rtnl_unlock() */
extern void netdev_run_todo(void);

static inline void dev_put(struct net_device *dev)
{
	atomic_dec(&dev->refcnt);
}

#define __dev_put(dev) atomic_dec(&(dev)->refcnt)
#define dev_hold(dev) atomic_inc(&(dev)->refcnt)

/* Carrier loss detection, dial on demand. The functions netif_carrier_on
 * and _off may be called from IRQ context, but it is caller
 * who is responsible for serialization of these calls.
 */

extern void linkwatch_fire_event(struct net_device *dev);

static inline int netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

extern void __netdev_watchdog_up(struct net_device *dev);

/**
 * ���豸������⵽�����豸�ϴ����ź�ʱ��������netif_carrier_on����.
 * �����Ǽ��������ĵ�������״̬�ı�ĵ������ 
 *		�������γ��������� 
 *		������һ�˵��豸�رջ��ֹ����Щ�豸��hub�����š�·������pc��������
 */
static inline void netif_carrier_on(struct net_device *dev)
{
	/**
	 * ���dev->state��__LINK_STATE_NOCARRIER��־λ
	 */
	if (test_and_clear_bit(__LINK_STATE_NOCARRIER, &dev->state))
		/**
		 * ����һ������״̬�ı��¼����ύ��linkwatch_fire_event����
		 */
		linkwatch_fire_event(dev);
	/**
	 * ����豸��ʹ�ܣ�������һ�����Ӷ�ʱ������ʱ������������ʹ�ã�������Ƿ���ʧ�ܻ���һ��ʱ���(���������ʱ����ʱ)��
	 */
	if (netif_running(dev))
		__netdev_watchdog_up(dev);
}

/**
 * ���豸������⵽�����豸�϶�ʧ�ź�ʱ��������netif_carrier_off������
 */
static inline void netif_carrier_off(struct net_device *dev)
{
	/**
	 * ����dev->state��__LINK_STATE_NOCARRIER��־λ
	 */
	if (!test_and_set_bit(__LINK_STATE_NOCARRIER, &dev->state))
		/**
		 * ����һ������״̬�ı��¼����ύ��linkwatch_fire_event����
		 */
		linkwatch_fire_event(dev);
}

/* Hot-plugging. */
static inline int netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

/**
 * �����豸ʱ������һЩ���������¼���
 */
static inline void netif_device_detach(struct net_device *dev)
{
	/**
	 * ����������dev->state��__LINK_STATE_PRESENT��־λ����Ϊ�豸��ʱ���ܹ�������
	 */
	 */
	if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
	    /*
		 * ����豸��netif_stop_queueʹ�ܻ��ֹ������У��Է�ֹ�豸���ڷ����κ������İ���
	 	 * ע�⣺��ע����豸����Ҫʹ�ܣ����豸����֤������ȡ�ں�ָ�ɵ��豸������ע�᣻���ǣ��豸ֱ������ȷ���û���������ʱ����ʹ��(��˿���)��
	 	 */
	 	netif_stop_queue(dev);
	}
}

/**
 * �����豸ʱ������һЩ���������¼���
 */
static inline void netif_device_attach(struct net_device *dev)
{
	/**
	 * ����dev->state��__LINK_STATE_PRESENT��־λ����Ϊ�豸���ڿ����ˡ�
	 */
	if (!test_and_set_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
	    /**
	     * ����豸�ڹ���ǰ��ʹ�ܣ���netif_wake_queue��������ʹ������ڶ��У����������������¿�������Ӷ�ʱ��
	     */
		netif_wake_queue(dev);
 		__netdev_watchdog_up(dev);
	}
}

/*
 * Network interface message level settings
 */
#define HAVE_NETIF_MSG 1

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	/* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) - 1;
}

/* Schedule rx intr now? */

static inline int netif_rx_schedule_prep(struct net_device *dev)
{
	return netif_running(dev) &&
		!test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* Add interface to tail of rx poll list. This assumes that _prep has
 * already been called and returned 1.
 */

static inline void __netif_rx_schedule(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	dev_hold(dev);
	list_add_tail(&dev->poll_list, &__get_cpu_var(softnet_data).poll_list);
	if (dev->quota < 0)
		dev->quota += dev->weight;
	else
		dev->quota = dev->weight;
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	local_irq_restore(flags);
}

/* Try to reschedule poll. Called by irq handler. */
/**
 * ���豸����ʹ��NAPIʱ���������жϴ������е���������ʹ�������հ����жϡ�
 */
static inline void netif_rx_schedule(struct net_device *dev)
{
	/**
	 * ����豸ȷʵ�����У�������Ӧ�����ж�û�б�ʹ�ܡ�
	 */
	if (netif_rx_schedule_prep(dev))
		/**
		 * ���豸��ӵ�poll_list�������������жϡ�
		 */
		__netif_rx_schedule(dev);
}

/* Try to reschedule poll. Called by dev->poll() after netif_rx_complete().
 * Do not inline this?
 */
static inline int netif_rx_reschedule(struct net_device *dev, int undo)
{
	if (netif_rx_schedule_prep(dev)) {
		unsigned long flags;

		dev->quota += undo;

		local_irq_save(flags);
		list_add_tail(&dev->poll_list, &__get_cpu_var(softnet_data).poll_list);
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		local_irq_restore(flags);
		return 1;
	}
	return 0;
}

/* Remove interface from poll list: it must be in the poll list
 * on current cpu. This primitive is called by dev->poll(), when
 * it completes the work. The device cannot be out of poll list at this
 * moment, it is BUG().
 */
/**
 * ���豸��poll_list������ɾ����
 */
static inline void netif_rx_complete(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
	local_irq_restore(flags);
}

/**
 * ��ʱ��������߽�ֹ��ѯ
 * �Ⲣ����ζ���豸�ص����ж�����ģʽ����ѯ������ĳ���豸�ϱ���ֹ�����磬���豸��Ҫ���ã�����һЩ������Ч��
 */
static inline void netif_poll_disable(struct net_device *dev)
{
	/**
	 * ���__LINK_STATE_RX_SCHEDû�б����ã�˵���豸û����poll_list�С�
	 * ��ô���򵥵������������ء�
	 * ����˯�ߣ����ȴ�__LINK_STATE_RX_SCHED��־�������Ȼ�������ñ�־��
	 * ���ñ���־���豸�����ٱ����뵽poll_list���У�Ҳ����ʱ��ֹ��poll.
	 */
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

/**
 * ��ʱ��������߽�ֹ��ѯ
 * �Ⲣ����ζ���豸�ص����ж�����ģʽ����ѯ������ĳ���豸�ϱ���ֹ�����磬���豸��Ҫ���ã�����һЩ������Ч��
 */
static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* same as netif_rx_complete, except that local_irq_save(flags)
 * has already been issued
 */
static inline void __netif_rx_complete(struct net_device *dev)
{
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}

/* These functions live elsewhere (drivers/net/net_init.c, but related) */

extern void		ether_setup(struct net_device *dev);

/* Support for loadable net-drivers */
extern struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *));
extern int		register_netdev(struct net_device *dev);
extern void		unregister_netdev(struct net_device *dev);
/* Functions used for multicast support */
extern void		dev_mc_upload(struct net_device *dev);
extern int 		dev_mc_delete(struct net_device *dev, void *addr, int alen, int all);
extern int		dev_mc_add(struct net_device *dev, void *addr, int alen, int newonly);
extern void		dev_mc_discard(struct net_device *dev);
extern void		dev_set_promiscuity(struct net_device *dev, int inc);
extern void		dev_set_allmulti(struct net_device *dev, int inc);
extern void		netdev_state_change(struct net_device *dev);
/* Load a device via the kmod */
extern void		dev_load(const char *name);
extern void		dev_mcast_init(void);
extern int		netdev_max_backlog;
extern int		weight_p;
extern unsigned long	netdev_fc_xoff;
extern atomic_t netdev_dropping;
extern int		netdev_set_master(struct net_device *dev, struct net_device *master);
extern int skb_checksum_help(struct sk_buff *skb, int inward);
/* rx skb timestamps */
extern void		net_enable_timestamp(void);
extern void		net_disable_timestamp(void);

#ifdef CONFIG_SYSCTL
extern char *net_sysctl_strdup(const char *s);
#endif

#endif /* __KERNEL__ */

#endif	/* _LINUX_DEV_H */
