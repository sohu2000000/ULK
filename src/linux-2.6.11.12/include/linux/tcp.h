/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>

/* TCP�ײ� */
struct tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__u16	window;
	__u16	check;
	__u16	urg_ptr;
};


enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,	 /* now a valid state */

  TCP_MAX_STATES /* Leave at the end! */
};

#define TCP_STATE_MASK	0xF
#define TCP_ACTION_FIN	(1 << 7)

enum {
  TCPF_ESTABLISHED = (1 << 1),
  TCPF_SYN_SENT  = (1 << 2),
  TCPF_SYN_RECV  = (1 << 3),
  TCPF_FIN_WAIT1 = (1 << 4),
  TCPF_FIN_WAIT2 = (1 << 5),
  TCPF_TIME_WAIT = (1 << 6),
  TCPF_CLOSE     = (1 << 7),
  TCPF_CLOSE_WAIT = (1 << 8),
  TCPF_LAST_ACK  = (1 << 9),
  TCPF_LISTEN    = (1 << 10),
  TCPF_CLOSING   = (1 << 11) 
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__u32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block {
	__u32	start_seq;
	__u32	end_seq;
};

enum tcp_congestion_algo {
	TCP_RENO=0,
	TCP_VEGAS,
	TCP_WESTWOOD,
	TCP_BIC,
};

/* ���ڱ�����յ���TCPѡ����Ϣ */
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	/* ��¼�ӽ��յ��Ķ���ȡ��ʱ������õ�ts_recent��ʱ�䣬���ڼ��ts_recent����Ч�ԡ��������24������Ϊts_recent��Ч */
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	/* ��һ�������͵�TCP���е�ʱ�������ֵ */
	__u32	ts_recent;	/* Time stamp to echo next		*/
	/* ���һ�ν��յ��Զ˵�TCP�ε�ʱ���ѡ���е�ʱ���ֵ */
	__u32	rcv_tsval;	/* Time stamp value             	*/
	/* ���һ�ν��յ���TCP���е�ʱ�������Ӧ�� */
	__u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	/* ���һ�ν��յ��Ķ��Ƿ����ʱ���ѡ�� */
	char	saw_tstamp;	/* Saw TIMESTAMP on last packet		*/
	/* �Ƿ�����ʱ���ѡ�� */
	char	tstamp_ok;	/* TIMESTAMP seen on SYN packet		*/
	/* �Ƿ�֧��SACK */
	char	sack_ok;	/* SACK seen on SYN packet		*/
	/* ���շ��Ƿ�֧�ִ����������ӣ�ֻ�ܳ�����SYN���� */
	char	wscale_ok;	/* Wscale seen on SYN packet		*/
	/* ���ʹ����������� */
	__u8	snd_wscale;	/* Window scaling received from sender	*/
	/* ���մ����������� */
	__u8	rcv_wscale;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	/* ��ʶ�´η��͵Ķ���SACKѡ���Ƿ����D-SACK */
	__u8	dsack;		/* D-SACK is scheduled			*/
	/* ��һ�������͵Ķ���SACKѡ���е�SACK�����С�����Ϊ0�������Ϊû��SACK�� */
	__u8	eff_sacks;	/* Size of SACK array to send with next packet */
	/* ��һ�������͵Ķ���SACKѡ���е�SACK������ */
	__u8	num_sacks;	/* Number of SACK blocks		*/
	__u8	__pad;
	/* �û����õ�MSS���� */
	__u16	user_mss;  	/* mss requested by user in ioctl */
	/* �����ӵĶԶ�MSS���� */
	__u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

/**
 * TCP������ƿ顣
 */
struct tcp_sock {
	/* inet_sock has to be the first member of tcp_sock */
	struct inet_sock	inet;/* IPV4������ƿ飬�����ǵ�һ���ֶ� */
	/* TCP�ײ����ȣ�����ѡ�� */
	int	tcp_header_len;	/* Bytes of tcp header to send		*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
    /**
     * �ײ�Ԥ���־�����ڷ��ͺͽ���SYN�����´��ڼ�����ʱ�����øñ�־ 
	 * ����ʱ��������кŵ����ض����ж�ִ�п��ٻ�������·����������
     */
	__u32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	/* �ȴ����յ���һ��TCP�ε���ţ�ÿ���յ�һ���κ����ø�ֵ */
 	__u32	rcv_nxt;	/* What we want to receive next 	*/
	/* �ȴ����͵���һ��TCP�ε���� */
 	__u32	snd_nxt;	/* Next sequence we send		*/

	/* ������Ķ��У�����һ��δȷ�϶ε���� */
 	__u32	snd_una;	/* First byte we want an ack for	*/
	/**
	 * ������͵�С��(С��MSS��)�����һ���ֽ���ţ��ڳɹ����Ͷκ��������С��MSS�������¸��ֶΡ� 
	 * ��Ҫ���������Ƿ�����Nagle�㷨��
	 */
 	__u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	/* ���һ���յ�ACK�ε�ʱ�䣬����TCP��� */
	__u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	/* ���һ�η������ݰ���ʱ�䣬��Ҫ����ӵ�����ڵ����� */
	__u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	/* ָ����֮�󶨵ı��ض˿���Ϣ���ڰ󶨹����б����� */
	struct tcp_bind_bucket *bind_hash;
	/* Delayed ACK control data */
	/* �ӳ�ȷ�Ͽ������ݿ� */
	struct {
		/* ��ǰ��Ҫ���͵�ACK�Ľ��������״̬����TCP_ACK_SCHED */
		__u8	pending;	/* ACK is pending */
		/* �ڿ��ٷ���ģʽ�У����Կ��ٷ���ACK������ */
		__u8	quick;		/* Scheduled number of quick acks	*/
		/* ��ʶ�Ƿ����û���ÿ���ȷ��ģʽ��ͨ��TCP_QUICKACKѡ�����á� */
		__u8	pingpong;	/* The session is interactive		*/
		/* ��ȻӦ������ACK�������׽ӿ�����ռ���ˣ���˷��͹��̱����� */
		__u8	blocked;	/* Delayed ACK was blocked by socket lock*/
		/* ����������ʱȷ�ϵĹ�ֵ���ڽ��յ�TCP��ʱ����ݱ������ϴν��յ�ʱ������������ֵ�� */
		__u32	ato;		/* Predicted tick of soft clock		*/
		/* ��ǰ����ʱȷ��ʱ�䣬��ʱ��ᷢ��ACK */
		unsigned long timeout;	/* Currently scheduled timeout		*/
		/* ���һ�ν��յ����ݰ���ʱ�� */
		__u32	lrcvtime;	/* timestamp of last received data packet*/
		/* ���һ�ν��յ����ݶεĳ��ȣ����ڼ���rcv_mss */
		__u16	last_seg_size;	/* Size of last incoming segment	*/
		/* ��������յ��Ķγ��ȼ��������mss����Ҫ����ȷ���Ƿ�ִ����ʱȷ�ϡ� */
		__u16	rcv_mss;	/* MSS used for delayed ACK decisions	*/ 
	} ack;

	/* Data for direct copy to user */
	/* �������Ƹ������ݵ��û����̵Ŀ��ƿ飬���������û��ռ仺�漰�䳤�ȣ�prequeue���м���ռ�õ��ڴ� */
	struct {
		/* ���δ����tcp_low_latecy(һ��δ����)��TCP�ν����Ȼ��浽�˶��У�ֱ������������ȡʱ���������յ����ն����д��� */
		struct sk_buff_head	prequeue;
		/* ���δ����tcp_low_latecy(һ��δ����),��ǰ���ڶ�ȡTCP���Ľ��̣����ΪNULL��ʾû�н��̶�ȡ���� */
		struct task_struct	*task;
		/* ���δ����tcp_low_latecy(һ��δ����),����������ݵ��û��ռ��ַ���ڽ��մ���TCP��ʱֱ�Ӹ��Ƶ��û��ռ� */
		struct iovec		*iov;
		/* prequeue���е�ǰ���ĵ��ڴ� */
		int			memory;
		/* �û������п���ʹ�õĻ����С����recv��ϵͳ���õ�len������ʼ�� */
		int			len;
	} ucopy;

	/* ���·��ʹ��ڵ��Ǹ�ACK�ε���ţ������ж��Ƿ���Ҫ���´��ڡ���������յ���ACK�δ��ڴ�ֵ������Ҫ���¡� */
	__u32	snd_wl1;	/* Sequence for window update		*/
	/* ���շ��ṩ�Ľ��մ��ڴ�С�������ͷ����ʹ��ڴ�С */
	__u32	snd_wnd;	/* The window we expect to receive	*/
	/* ���շ�ͨ����������մ���ֵ�� */
	__u32	max_window;	/* Maximal window ever seen from peer	*/
	/* ���һ�θ��µ�·��MTU */
	__u32	pmtu_cookie;	/* Last pmtu seen by socket		*/
	/* ���ͷ���ǰ��ЧMSS */
	__u32	mss_cache;	/* Cached effective mss, not including SACKS */
	__u16	mss_cache_std;	/* Like mss_cache, but without TSO */
	/* IP�ײ���ѡ��ֳ��� */
	__u16	ext_header_len;	/* Network protocol overhead (IP/IPv6 options) */
	__u16	ext2_header_len;/* Options depending on route */
	/* �����ش�״̬ */
	__u8	ca_state;	/* State of fast-retransmit machine 	*/
	/* ��ʱ�ش��Ĵ��� */
	__u8	retransmits;	/* Number of unrecovered RTO timeouts.	*/

	/* ���ش���ʱ����ʱ��������F-RTO����£�������������͵���һ��TCP�ε���ţ�����F-RTOʱʹ�� */
	__u32	frto_highmark;	/* snd_nxt when RTO occurred */
	/**
	 * �ڲ�֧��SACKʱ��Ϊ�����������յ��ظ�ȷ�϶�������ٻָ��׶ε��ظ�ȷ������ֵ��
	 * ��֧��SACKʱ����û��ȷ����ʧ��������£���TCP���п�������������ݶ�����
	 */
	__u8	reordering;	/* Packet reordering metric.		*/
	/**
	 * �ڴ��ͳ�ʱ�󣬼�¼������F-RTO�㷨ʱ���յ�ACK�ε���Ŀ��
	 */
	__u8	frto_counter;	/* Number of new acks after RTO */

	__u8	adv_cong;	/* Using Vegas, Westwood, or BIC */
	__u8	defer_accept;	/* User waits for some data after accept() */

/* RTT measurement */
	/* ƽ����RTT��Ϊ���⸡�����㣬����Ŵ�8���󱣴� */
	__u32	srtt;		/* smoothed round trip time << 3	*/
	/* RTTƽ��ƫ�ֵԽ��˵������Խ���� */
	__u32	mdev;		/* medium deviation			*/
	/* ÿ�η��ʹ����ڵĶα�ȫ��ȷ�Ϲ����У�RTTƽ��ƫ������ֵ���������������Χ�� */
	__u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/* ƽ����RTTƽ��ƫ���mdev����õ�����������RTO */
	__u32	rttvar;		/* smoothed mdev_max			*/
	/* ����rttvarʱ����� */
	__u32	rtt_seq;	/* sequence number to update rttvar	*/
	/* ��ʱ�ش���ʱ�䣬������ʱ�䳬����ֵʱ��Ϊ����ʧ�ܡ��������������̬���㡣 */
	__u32	rto;		/* retransmit timeout			*/

	/* ����(�뿪���Ͷ���)��û�еõ�ȷ�ϵĶ���Ŀ */
	__u32	packets_out;	/* Packets which are "in flight"	*/
	/**
	 * �Ѿ��뿪������δȷ�ϵ�TCP�Σ������������:
	 *		һ��ͨ��SACKȷ�ϵĶ�
	 *		�����Ѿ���ʧ�Ķ�
	 */
	__u32	left_out;	/* Packets which leaved network	*/
	/* �ش���δ�õ�ȷ�ϵĶ� */
	__u32	retrans_out;	/* Retransmitted packets out		*/
	/* ���ڼ��������ʱ������һ���趨ֵ */
	__u8	backoff;	/* backoff				*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
 	/**
 	 * �Ƿ�����Nagle�㷨�����㷨�ѽ�С�Ķ���װ�ɸ���ĶΣ��������С����������ӵ�������⡣�μ�TCP_NODELAY��TCP_CORKѡ�
 	 *		TCP_NAGLE_OFF:		�ر�nagle�㷨
 	 *		TCP_NAGLE_CORK:		��Nagle�㷨�����Ż���ʹ���͵Ķξ�����Я����������ݣ�������200ms��ʱ�����ơ�
 	 *		TCP_NAGLE_PUSH:		������Nagle�㷨������������Ż���
 	 */
	__u8	nonagle;	/* Disable Nagle algorithm?             */
	/* ����̽����������Ϊ127�� */
	__u8	keepalive_probes; /* num of allowed keep alive probes	*/

	/* ������ʱ���������Զ�ʱ�����ͳ�ȥ��δ��ȷ�ϵ�TCP����Ŀ�����յ�ACK֮����0 */
	__u8	probes_out;	/* unanswered 0 window probes		*/
	/* ���յ���TCPѡ�� */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	/* ӵ������ʱ�������ķ�ֵ */
 	__u32	snd_ssthresh;	/* Slow start size threshold		*/
	/* ��ǰӵ�����ڵĴ�С */
 	__u32	snd_cwnd;	/* Sending congestion window		*/
	/* �Դ��ϴε���ӵ�����ڵ�ĿǰΪֹ���յ����ܵ�ACK���� */
 	__u16	snd_cwnd_cnt;	/* Linear increase counter		*/
	/* ��������ӵ������ֵ����ʼֵΪ65535 */
	__u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	/* �ӷ��Ͷ��з�����δ�õ�ȷ�ϵĶ����������ڼ���ӵ������ʱ����ӵ������ */
	__u32	snd_cwnd_used;
	/* ��¼���һ�μ���ӵ�����ڵ�ʱ�䡣 */
	__u32	snd_cwnd_stamp;

	/* Two commonly used timers in both sender and receiver paths. */
	/* ���ָ��ʱ����û�н��յ�ACK������Ϊ����ʧ�� */
	unsigned long		timeout;
	/* �ش���ʱ���ͳ�����ʱ����ͨ��pending��־�����֡� */
 	struct timer_list	retransmit_timer;	/* Resend (no ack)	*/
	/* �ӳٷ���ACK�Ķ�ʱ�� */
 	struct timer_list	delack_timer;		/* Ack delay 		*/

	/* ���򻺴���У������ݴ���յ��������TCP�� */
	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	struct tcp_func		*af_specific;	/* Operations which are AF_INET{4,6} specific	*/

	/* ��ǰ���մ��ڵĴ�С */
 	__u32	rcv_wnd;	/* Current receiver window		*/
	/* ���յ���û��ȷ�ϵ���С�Ķ� */
	__u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	/* �Ѿ�������ն����е����һ���ֽڵ���� */
	__u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	/* һ���ʾ�Ѿ��������ͳ�ȥ�����һ���ֽ���ţ���ʱҲ��ʾ��������ȥ�����һ���ֽڵ���� */
	__u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	/* ��û�д��ں˿ռ临�Ƶ��û��ռ�Ķεĵ�һ���ֽڵ���� */
	__u32	copied_seq;	/* Head of yet unread data		*/

/*	SACKs data	*/
	/* �洢���ڻظ��Զ˵�D-SACK��Ϣ */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	/* �洢���ڻظ��Զ˵�SACK��Ϣ */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	/* �������ڵ����ֵ����TCP��������ʱ�����г�ʼ����̫��ᵼ�»������ڲ�����TCP�ײ��б�ʾ�� */
	__u32	window_clamp;	/* Maximal window to advertise		*/
	/* ��ǰ���մ��ڴ�С�ķ�ֵ�����ڿ��ƻ������ڵĻ������� */
	__u32	rcv_ssthresh;	/* Current window clamp			*/
	/* �����ܽ��յ�MSS���ޣ��ڽ�������ʱͨ��Է� */
	__u16	advmss;		/* Advertised MSS			*/

	/* �ڽ���TCP����ʱ����������Է���SYN��SYN+ACK�εĴ��� */
	__u8	syn_retries;	/* num of allowed syn retries */
	/* ��ʽӵ��֪ͨ״̬λ����TCP_ECN_OK */
	__u8	ecn_flags;	/* ECN status bits.			*/
	/* ������RTO�㷨������£�·��MTU̽��ɹ�������ӵ������״̬ʱ�����ssthreshֵ����Ҫ���ڳ���ӵ������ʱ���ָ���������ֵ */
	__u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	__u16	__pad1;
	/* ���ͺ�ʧ�ڴ�������жε�������Ŀǰ��TCP�У�lost_out==packets_out */
	__u32	lost_out;	/* Lost packets			*/
	/* ����SACKʱ��ͨ��SACK��TCPѡ���ʶ�ѽ��յ��ε������� */
	__u32	sacked_out;	/* SACK'd packets			*/
	/* SACKѡ���У����շ����յ��Ķ���������snd_una֮���ж�����FACK�㷨�������㶪ʧ�������ϵĶ����� */
	__u32	fackets_out;	/* FACK'd packets			*/
	/* ��¼����ӵ��ʱ��snd_nxt����ʶ�ش����е�β�� */
	__u32	high_seq;	/* snd_nxt at onset of congestion	*/

	/**
	 * ��������ʱ����¼��һ��SYN�εķ���ʱ�䣬�������ACK����Ƿ���ơ� 
	 * �����ݴ���׶Σ������ͳ�ʱ�ش�ʱ����¼�ϴ��ش��׶ε�һ���ش��εķ���ʱ�䣬�����ж��Ƿ���Խ���ӵ��������
	 */
	__u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	/* ��ʹ��F-RTO�㷨���г�ʱ����ʱ�������Recovery�����ش��������Loss��ʼ������ʱ����¼��ʱ��snd_una������ش���ʼ�㡣 */
	__u32	undo_marker;	/* tracking retrans started here. */
	/* �ڻָ�ӵ������֮ǰ�ɽ��г������ش��������ڽ���FRTO�㷨��ӵ��״̬Lossʱ��0���Ǽ��ӵ������������֮һ�� */
	int	undo_retrans;	/* number of undoable retransmissions. */
	/* �������ݵ���ţ������ڶε���źͽ���ָ����Ӷ��õ� */
	__u32	urg_seq;	/* Seq of received urgent pointer */
	/* ��8λ�洢���յ��Ľ������ݣ���8λ���ڱ�ʶ�������ݵ�״̬����TCP_URG_NOTYET */
	__u16	urg_data;	/* Saved octet of OOB data and control flags */
	/**
	 * �����ʱ���¼� 
	 */
	__u8	pending;	/* Scheduled timer event	*/
	/* ��ʶ���ڽ���ģʽ�����߽��շ����������Ѿ�������ͨ�������� */
	__u8	urg_mode;	/* In urgent mode		*/
	/* ��������ָ�룬���������ݵ���š� */
	__u32	snd_up;		/* Urgent pointer		*/

	/* ���������е��ش����� */
	__u32	total_retrans;	/* Total retransmits for entire connection */

	/* The syn_wait_lock is necessary only to avoid proc interface having
	 * to grab the main lock sock while browsing the listening hash
	 * (otherwise it's deadlock prone).
	 * This lock is acquired in read mode only from listening_get_next()
	 * and it's acquired in write mode _only_ from code that is actively
	 * changing the syn_wait_queue. All readers that are holding
	 * the master sock lock don't need to grab this lock in read mode
	 * too as the syn_wait_queue writes are always protected from
	 * the main sock lock.
	 */
	/* ����listen_opt�ṹ��Ա�Ŀ����� */
	rwlock_t		syn_wait_lock;
	/* �ڽ�������ʱ������������������� */
	struct tcp_listen_opt	*listen_opt;

	/* FIFO of established children */
	/* �ȴ����յ������������ */
	struct open_request	*accept_queue;
	struct open_request	*accept_queue_tail;

	/* TCP����̽��ǰ��TCP���ӵĿ���ʱ�� */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	/* ���ͱ���̽��ļ�� */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	/* TCPǨ�Ƶ�CLOSED״̬֮ǰ������FIN_WAIT_2״̬��ʱ�䡣 */
	int			linger2;

	/* ������tcp_syncookies������£���������ʱ��¼����syn�ε�ʱ�䣬������������Ƿ�ʱ */
	unsigned long last_synq_overflow; 

/* Receiver side RTT estimation */
	/* �洢���շ���RTT����ֵ���������Ƶ���TCP���ջ������ռ�ļ��ʱ�䲻��С��RTT */
	struct {
		__u32	rtt;/* ���շ������RTT */
		__u32	seq;/* �ڽ��յ��Ķ�û��ʱ���������£����½��շ�RTTʱ�Ľ��մ����Ҷ���ţ�ÿ���һ�����ո���һ�ν��շ�RTT */
		__u32	time;/* �ڶ�û��ʱ���������£���¼ÿ�θ���RTT��ʱ�� */
	} rcv_rtt_est;

/* Receiver queue space */
	/* ��������TCP���ջ���ռ�ͽ��մ��ڴ�С��Ҳ����ʵ��ͨ�����ڽ��մ����������������ƵĹ��ܡ�ÿ�ν����ݸ��Ƶ��û��ռ䣬�������µ�TCP���ջ���ռ��С�� */
	struct {
		int	space;/* ���ڵ������ջ���Ĵ�С */
		__u32	seq;/* �Ѹ��Ƶ��û��ռ��TCP����� */
		__u32	time;/* ��¼���һ�ν��е�����ʱ�� */
	} rcvq_space;

/* TCP Westwood structure */
        struct {
                __u32    bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
                __u32    bw_est;           /* bandwidth estimate */
                __u32    rtt_win_sx;       /* here starts a new evaluation... */
                __u32    bk;
                __u32    snd_una;          /* used for evaluating the number of acked bytes */
                __u32    cumul_ack;
                __u32    accounted;
                __u32    rtt;
                __u32    rtt_min;          /* minimum observed RTT */
        } westwood;

/* Vegas variables */
	struct {
		__u32	beg_snd_nxt;	/* right edge during last RTT */
		__u32	beg_snd_una;	/* left edge  during last RTT */
		__u32	beg_snd_cwnd;	/* saves the size of the cwnd */
		__u8	doing_vegas_now;/* if true, do vegas for this RTT */
		__u16	cntRTT;		/* # of RTTs measured within last RTT */
		__u32	minRTT;		/* min of RTTs measured within last RTT (in usec) */
		__u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) */
	} vegas;

	/* BI TCP Parameters */
	struct {
		__u32	cnt;		/* increase cwnd by 1 after this number of ACKs */
		__u32 	last_max_cwnd;	/* last maximium snd_cwnd */
		__u32	last_cwnd;	/* the last snd_cwnd */
		__u32   last_stamp;     /* time when updated last_cwnd */
	} bictcp;
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
