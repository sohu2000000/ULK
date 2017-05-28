/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		PF_INET protocol family socket handler.
 *
 * Version:	$Id: af_inet.c,v 1.137 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 * Changes (see also sock.c)
 *
 *		piggy,
 *		Karl Knutson	:	Socket protocol table
 *		A.N.Kuznetsov	:	Socket death error in accept().
 *		John Richardson :	Fix non blocking error in connect()
 *					so sockets that fail to connect
 *					don't return -EINPROGRESS.
 *		Alan Cox	:	Asynchronous I/O support
 *		Alan Cox	:	Keep correct socket pointer on sock
 *					structures
 *					when accept() ed
 *		Alan Cox	:	Semantics of SO_LINGER aren't state
 *					moved to close when you look carefully.
 *					With this fixed and the accept bug fixed
 *					some RPC stuff seems happier.
 *		Niibe Yutaka	:	4.4BSD style write async I/O
 *		Alan Cox,
 *		Tony Gale 	:	Fixed reuse semantics.
 *		Alan Cox	:	bind() shouldn't abort existing but dead
 *					sockets. Stops FTP netin:.. I hope.
 *		Alan Cox	:	bind() works correctly for RAW sockets.
 *					Note that FreeBSD at least was broken
 *					in this respect so be careful with
 *					compatibility tests...
 *		Alan Cox	:	routing cache support
 *		Alan Cox	:	memzero the socket structure for
 *					compactness.
 *		Matt Day	:	nonblock connect error handler
 *		Alan Cox	:	Allow large numbers of pending sockets
 *					(eg for big web sites), but only if
 *					specifically application requested.
 *		Alan Cox	:	New buffering throughout IP. Used
 *					dumbly.
 *		Alan Cox	:	New buffering now used smartly.
 *		Alan Cox	:	BSD rather than common sense
 *					interpretation of listen.
 *		Germano Caronni	:	Assorted small races.
 *		Alan Cox	:	sendmsg/recvmsg basic support.
 *		Alan Cox	:	Only sendmsg/recvmsg now supported.
 *		Alan Cox	:	Locked down bind (see security list).
 *		Alan Cox	:	Loosened bind a little.
 *		Mike McLagan	:	ADD/DEL DLCI Ioctls
 *	Willy Konynenberg	:	Transparent proxying support.
 *		David S. Miller	:	New socket lookup architecture.
 *					Some other random speedups.
 *		Cyrus Durgin	:	Cleaned up file for kmod hacks.
 *		Andi Kleen	:	Fix inet_stream_connect TCP race.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/netfilter_ipv4.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/smp_lock.h>
#include <linux/inet.h>
#include <linux/igmp.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/inet_common.h>
#include <net/xfrm.h>
#ifdef CONFIG_IP_MROUTE
#include <linux/mroute.h>
#endif

DEFINE_SNMP_STAT(struct linux_mib, net_statistics);

#ifdef INET_REFCNT_DEBUG
atomic_t inet_sock_nr;
#endif

extern void ip_mc_drop_socket(struct sock *sk);

/* The inetsw table contains everything that inet_create needs to
 * build a new socket.
 */
static struct list_head inetsw[SOCK_MAX];
static DEFINE_SPINLOCK(inetsw_lock);

/* New destruction routine */

/* ���׽ӿڱ��ͷ�ʱ������һЩ������ */
void inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&sk->sk_error_queue);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		printk("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		printk("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	BUG_TRAP(!atomic_read(&sk->sk_rmem_alloc));
	BUG_TRAP(!atomic_read(&sk->sk_wmem_alloc));
	BUG_TRAP(!sk->sk_wmem_queued);
	BUG_TRAP(!sk->sk_forward_alloc);

	if (inet->opt)
		kfree(inet->opt);
	dst_release(sk->sk_dst_cache);
#ifdef INET_REFCNT_DEBUG
	atomic_dec(&inet_sock_nr);
	printk(KERN_DEBUG "INET socket %p released, %d are still alive\n",
	       sk, atomic_read(&inet_sock_nr));
#endif
}

/*
 *	The routines beyond this point handle the behaviour of an AF_INET
 *	socket object. Mostly it punts to the subprotocols of IP to do
 *	the work.
 */

/*
 *	Automatically bind an unbound socket.
 */

static int inet_autobind(struct sock *sk)
{
	struct inet_sock *inet;
	/* We may need to bind the socket. */
	lock_sock(sk);
	inet = inet_sk(sk);
	if (!inet->num) {
		if (sk->sk_prot->get_port(sk, 0)) {
			release_sock(sk);
			return -EAGAIN;
		}
		inet->sport = htons(inet->num);
	}
	release_sock(sk);
	return 0;
}

/*
 *	Move a socket into listening state.
 */
/* ��һ��socketת��listen״̬ */
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	/* ���ϵͳ���õ�״̬�����ͣ�������Ϸ����˳� */
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	/* ����Ȳ���TCPF_CLOSEҲ����TCPF_LISTEN״̬��Ҳ�˳� */
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = tcp_listen_start(sk);/* ��ʼ���� */
		if (err)
			goto out;
	}
	/* ���ô�����ƿ�����Ӷ��г������� */
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}

/*
 *	Create an inet socket.
 */
/**
 * ����һ��IPV4��socket
 *		sock:		�Ѿ��������׽ӿ�
 *		protocol:	�׽ӿڵ�Э���
 */
static int inet_create(struct socket *sock, int protocol)
{
	struct sock *sk;
	struct list_head *p;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	char answer_no_check;
	int err;

	sock->state = SS_UNCONNECTED;/* ��ʼ���׽ӿ�״̬ */

	/* Look for the requested type/protocol pair. */
	answer = NULL;
	rcu_read_lock();
	list_for_each_rcu(p, &inetsw[sock->type]) {/* �����׽ӿ����ͱ���IPV4����  */
		answer = list_entry(p, struct inet_protosw, list);

		/* Check the non-wild match. */
		if (protocol == answer->protocol) {/* �Ƚϴ����Э�� */
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		answer = NULL;
	}

	err = -ESOCKTNOSUPPORT;
	if (!answer)/* �Ҳ�����Ӧ�Ĵ����Э�� */
		goto out_rcu_unlock;
	err = -EPERM;
	/* ���������͵��׽ӿ���Ҫ�ض�����������ǰ����û���������������˳� */
	if (answer->capability > 0 && !capable(answer->capability))
		goto out_rcu_unlock;
	err = -EPROTONOSUPPORT;
	if (!protocol)
		goto out_rcu_unlock;

	/* �����׽ӿڲ�Ľӿ� */
	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_no_check = answer->no_check;
	answer_flags = answer->flags;
	rcu_read_unlock();

	BUG_TRAP(answer_prot->slab != NULL);

	err = -ENOBUFS;
	/* ����Э����Ȳ������䴫����ƿ顣 */
	sk = sk_alloc(PF_INET, GFP_KERNEL,
		      answer_prot->slab_obj_size,
		      answer_prot->slab);
	if (sk == NULL)
		goto out;

	err = 0;
	sk->sk_prot = answer_prot;
	/* �����Ƿ���ҪУ��� */
	sk->sk_no_check = answer_no_check;
	/* �Ƿ�������õ�ַ�Ͷ˿� */
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = 1;

	inet = inet_sk(sk);

	if (SOCK_RAW == sock->type) {/* ��ԭʼ�׽ӿ� */
		inet->num = protocol;/* ���ñ��ض˿�ΪЭ��� */
		if (IPPROTO_RAW == protocol)/* �����RAWЭ�飬����Ҫ�Լ�����IP�ײ� */
			inet->hdrincl = 1;
	}

	if (ipv4_config.no_pmtu_disc)/* �Ƿ�֧��PMTU */
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->id = 0;

	sock_init_data(sock, sk);/* ��ʼ��������ƿ� */
	sk_set_owner(sk, sk->sk_prot->owner);

	/* ���׽ӿڱ��ͷ�ʱ������һЩ�������� */
	sk->sk_destruct	   = inet_sock_destruct;
	/* ����Э�����Э��� */
	sk->sk_family	   = PF_INET;
	sk->sk_protocol	   = protocol;
	/* ���ú󱸶��н��պ����� */
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;

#ifdef INET_REFCNT_DEBUG
	atomic_inc(&inet_sock_nr);
#endif

	if (inet->num) {/* ��������˱��ض˿ں� */
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->sport = htons(inet->num);/* ����������ı��ض˿ں� */
		/* Add to protocol hash chains. */
		sk->sk_prot->hash(sk);/* ��������ƿ���뵽���б��� */
	}

	if (sk->sk_prot->init) {/* ���ô����ĳ�ʼ���ص�����TCP��˵������tcp_v4_init_sock��UDPû�����ûص� */
		err = sk->sk_prot->init(sk);
		if (err)
			sk_common_release(sk);
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
/**
 * �ر��׽ӿ�ʱ�Ļص�
 */
int inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		long timeout;

		/* Applications forget to leave groups before exiting */
		ip_mc_drop_socket(sk);/* �뿪������鲥�� */

		/* If linger is set, we don't return until the close
		 * is complete.  Otherwise we return immediately. The
		 * actually closing is done the same either way.
		 *
		 * If the close is due to the process exiting, we never
		 * linger..
		 */
		timeout = 0;
		if (sock_flag(sk, SOCK_LINGER) &&/* ������LINGERѡ�� */
		    !(current->flags & PF_EXITING))/* ��ǰ����û�д����˳������� */
			timeout = sk->sk_lingertime;/* ��ȡ��ʱ�رյ�ʱ�� */
		sock->sk = NULL;
		sk->sk_prot->close(sk, timeout);/* ���ô�������ʱ�رսӿ� */
	}
	return 0;
}

/* It is off by default, see below. */
/**
 * ��0ʱ��Ӧ�ó�����п��ܰ����Ǳ���ַ������ַ��
 * ���磬�����������׽��ְ󶨵�һ����ַ����ʹ��֮�����Ľӿڹص��ˣ���
 */
int sysctl_ip_nonlocal_bind;

/**
 * IPV4��bind�ص�
 */
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {/* ��������ӿ���ʵ����bind���ã���ص�����Ŀǰֻ��SOCK_RAW���͵Ĵ����ʵ���˸ýӿ�raw_bind */
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))/* �����Ϸ��Լ�� */
		goto out;

	/**
	 * ȷ��һ��L3��ַ��һ���������㲥�Ͷಥ��ַ��
	 */	
	chk_addr_ret = inet_addr_type(addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (!sysctl_ip_nonlocal_bind &&/* ����󶨵����ؽӿڵĵ�ַ */
	    !inet->freebind &&
	    addr->sin_addr.s_addr != INADDR_ANY &&/* �󶨵�ַ���Ϸ� */
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	/* ���ָ���˶˿ںţ�����С��1024������Ҫ���Ӧ�ó����Ƿ�����Ӧ��Ȩ�� */
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);/* ���׽ӿڽ��м�������Ϊ����Ҫ����״̬�����ж� */

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	/**
	 * ���״̬��ΪCLOSE����ʾ�׽ӿ��Ѿ����ڻ״̬�������ٰ�
	 * �����Ѿ�ָ���˱��ض˿ںţ�Ҳ�����ٰ�
	 */
	if (sk->sk_state != TCP_CLOSE || inet->num)
		goto out_release_sock;

	/* ���õ�ַ��������ƿ��� */
	inet->rcv_saddr = inet->saddr = addr->sin_addr.s_addr;
	/* ����ǹ㲥���߶ಥ��ַ����Դ��ַʹ���豸��ַ�� */
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	/* ���ô�����get_port�����е�ַ�󶨡���tcp_v4_get_port��udp_v4_get_port */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->saddr = inet->rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	/* ���ñ�־����ʾ�Ѿ����˱��ص�ַ�Ͷ˿� */
	if (inet->rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->sport = htons(inet->num);
	/* ��û�����ӵ��Է������Զ�˵�ַ�Ͷ˿� */
	inet->daddr = 0;
	inet->dport = 0;
	/* ���·�ɻ��� */
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}

/* UDP connectϵͳ����ʵ�� */
int inet_dgram_connect(struct socket *sock, struct sockaddr * uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (uaddr->sa_family == AF_UNSPEC)/* ��ַ����Ч�������ӶϿ� */
		return sk->sk_prot->disconnect(sk, flags);

	if (!inet_sk(sk)->num && inet_autobind(sk))/* ���û�����ö˿ںţ���̬�󶨶˿� */
		return -EAGAIN;
	/* ���ô����ص�ip4_datagram_connect */
	return sk->sk_prot->connect(sk, (struct sockaddr *)uaddr, addr_len);
}

static long inet_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
/* connectϵͳ���õ��׽ӿڲ�ʵ�� */
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	lock_sock(sk);/* ��ȡ�׽ӿڵ��� */

	if (uaddr->sa_family == AF_UNSPEC) {/* δָ����ַ���ͣ����� */
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:/* ֻ�д�״̬���ܵ���connect */
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)/* �������TCP_CLOSE״̬��˵���Ѿ������� */
			goto out;

		/* ���ô����ӿ�tcp_connect�������Ӳ�����������SYN�� */
		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;

		/* ����SYN�κ�����״̬ΪSS_CONNECTING */
  		sock->state = SS_CONNECTING;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;/* ������Է�������ʽ�������ӣ���Ĭ�ϵķ���ֵΪEINPROGRESS����ʾ�������� */
		break;
	}

	/* ��ȡ���ӳ�ʱʱ�䣬���ָ����������ʽ���򲻵ȴ�ֱ�ӷ��� */
	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {/* ������SYN������״̬һ��Ϊ������״̬������������ӽ����ǳ��죬�����Խ��������״̬ */
		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo))/* �ȴ�������ɻ�ʱ */
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)/* ���е�����˵�����ӽ���ʧ�� */
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	sock->state = SS_CONNECTED;/* ���ӽ����ɹ�������Ϊ�Ѿ�����״̬ */
	err = 0;
out:
	release_sock(sk);
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
/* acceptϵͳ�������׽ӿڲ��ʵ�� */
int inet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk1 = sock->sk;/* �����׿ڻ�ô������ƿ� */
	int err = -EINVAL;
	/* ���ô����ĺ���inet_csk_accept����Ѿ���ɵ����ӵĴ�����ƿ飬���Ӵ�����ƿ� */
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err);

	if (!sk2)/* ʧ�ܷ��� */
		goto do_err;

	lock_sock(sk2);

	BUG_TRAP((1 << sk2->sk_state) &
		 (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_CLOSE));

	/* ���Ӵ�����ƿ��봫����ƿ�������� */
	sock_graft(sk2, newsock);

	/* �����׽ӿڵ�״̬ */
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk2);
do_err:
	return err;
}


/*
 *	This does both peername and sockname.
 */
/**
 * ��ȡ���˻��߶Զ˵ĵ�ַ�Ͷ˿�
 */
int inet_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sock *sk		= sock->sk;
	struct inet_sock *inet	= inet_sk(sk);
	struct sockaddr_in *sin	= (struct sockaddr_in *)uaddr;

	sin->sin_family = AF_INET;/* ��ַ�� */
	if (peer) {/* ��ȡ�Զ˵�ַ�Ͷ˿� */
		if (!inet->dport ||
		    (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&/* δ����״̬�����ܻ�ȡ�Զ���Ϣ */
		     peer == 1))
			return -ENOTCONN;
		sin->sin_port = inet->dport;
		sin->sin_addr.s_addr = inet->daddr;
	} else {/* ��ȡ���˵�ַ */
		__u32 addr = inet->rcv_saddr;
		if (!addr)
			addr = inet->saddr;
		sin->sin_port = inet->sport;
		sin->sin_addr.s_addr = addr;
	}
	memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	*uaddr_len = sizeof(*sin);
	return 0;
}

int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}


static ssize_t inet_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->num && inet_autobind(sk))
		return -EAGAIN;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);
	return sock_no_sendpage(sock, page, offset, size, flags);
}

/**
 * IPV4Э���shuwdownʵ��
 */
int inet_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	/* This should really check to make sure
	 * the socket is a TCP socket. (WHY AC...)
	 */
	/* ����λ���� */
	how++; /* maps 0->1 has the advantage of making bit 1 rcvs and
		       1->2 bit 2 snds.
		       2->3 */
	if ((how & ~SHUTDOWN_MASK) || !how)	/* MAXINT->0 *//* ������Ч��У�� */
		return -EINVAL;

	lock_sock(sk);
	if (sock->state == SS_CONNECTING) {
		if ((1 << sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE))
			sock->state = SS_DISCONNECTING;
		else
			sock->state = SS_CONNECTED;
	}

	switch (sk->sk_state) {
	case TCP_CLOSE:
		err = -ENOTCONN;
		/* Hack to wake up other listeners, who can poll for
		   POLLHUP, even on eg. unconnected UDP sockets -- RR */
	default:
		sk->sk_shutdown |= how;
		if (sk->sk_prot->shutdown)/* ����״̬�µ��ô�����shutdown */
			sk->sk_prot->shutdown(sk, how);
		break;

	/* Remaining two branches are temporary solution for missing
	 * close() in multithreaded environment. It is _not_ a good idea,
	 * but we have no choice until close() is repaired at VFS level.
	 */
	case TCP_LISTEN:
		if (!(how & RCV_SHUTDOWN))/* ��listen״̬�¹رն����ӣ���Ͽ����ӣ������˳� */
			break;
		/* Fall through */
	case TCP_SYN_SENT:/* ���ڽ������ӵĹ����� */
		/* ֱ�ӶϿ����� */
		err = sk->sk_prot->disconnect(sk, O_NONBLOCK);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		break;
	}

	/* Wake up anyone sleeping in poll. */
	sk->sk_state_change(sk);/* ���Ѵ�����ƿ��ϵĵȴ����� */
	release_sock(sk);
	return err;
}

/*
 *	ioctl() calls you can issue on an INET socket. Most of these are
 *	device configuration and stuff and very rarely used. Some ioctls
 *	pass on to the socket itself.
 *
 *	NOTE: I like the idea of a module for the config stuff. ie ifconfig
 *	loads the devconfigure module does its configuring and unloads it.
 *	There's a good 20K of config code hanging around the kernel.
 */

/**
 * IPV4���׽ӿ��ļ�ioctlʵ�֡�
 */
int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	int err = 0;

	switch (cmd) {
		case SIOCGSTAMP:/* ��ȡ������յ��ķ����ʱ��� */
			err = sock_get_timestamp(sk, (struct timeval __user *)arg);
			break;
		case SIOCADDRT:
		case SIOCDELRT:
		case SIOCRTMSG:
			err = ip_rt_ioctl(cmd, (void __user *)arg);/* ��ӻ���ɾ��·�� */
			break;
		case SIOCDARP:
		case SIOCGARP:
		case SIOCSARP:
			err = arp_ioctl(cmd, (void __user *)arg);/* �������޸ġ�ɾ������ȡARP��� */
			break;
		case SIOCGIFADDR:
		case SIOCSIFADDR:
		case SIOCGIFBRDADDR:
		case SIOCSIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCSIFNETMASK:
		case SIOCGIFDSTADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFPFLAGS:
		case SIOCGIFPFLAGS:
		case SIOCSIFFLAGS:
			err = devinet_ioctl(cmd, (void __user *)arg);/* ���豸�ӿڵ�ioctl�����������ַ�ȵ� */
			break;
		default:/* Ĭ������£������׽ӿڵ����紫���ioctl�ӿ������� */
			if (!sk->sk_prot->ioctl ||
			    (err = sk->sk_prot->ioctl(sk, cmd, arg)) ==
			    					-ENOIOCTLCMD)
				err = dev_ioctl(cmd, (void __user *)arg);
			break;
	}
	return err;
}

struct proto_ops inet_stream_ops = {
	.family =	PF_INET,
	.owner =	THIS_MODULE,
	.release =	inet_release,
	.bind =		inet_bind,
	.connect =	inet_stream_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	inet_accept,
	.getname =	inet_getname,
	.poll =		tcp_poll,
	.ioctl =	inet_ioctl,
	.listen =	inet_listen,
	.shutdown =	inet_shutdown,
	.setsockopt =	sock_common_setsockopt,
	.getsockopt =	sock_common_getsockopt,
	.sendmsg =	inet_sendmsg,
	.recvmsg =	sock_common_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	tcp_sendpage
};

struct proto_ops inet_dgram_ops = {
	.family =	PF_INET,
	.owner =	THIS_MODULE,
	.release =	inet_release,
	.bind =		inet_bind,
	.connect =	inet_dgram_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	inet_getname,
	.poll =		udp_poll,
	.ioctl =	inet_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	inet_shutdown,
	.setsockopt =	sock_common_setsockopt,
	.getsockopt =	sock_common_getsockopt,
	.sendmsg =	inet_sendmsg,
	.recvmsg =	sock_common_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	inet_sendpage,
};

/*
 * For SOCK_RAW sockets; should be the same as inet_dgram_ops but without
 * udp_poll
 */
static struct proto_ops inet_sockraw_ops = {
	.family =	PF_INET,
	.owner =	THIS_MODULE,
	.release =	inet_release,
	.bind =		inet_bind,
	.connect =	inet_dgram_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	inet_getname,
	.poll =		datagram_poll,
	.ioctl =	inet_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	inet_shutdown,
	.setsockopt =	sock_common_setsockopt,
	.getsockopt =	sock_common_getsockopt,
	.sendmsg =	inet_sendmsg,
	.recvmsg =	sock_common_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	inet_sendpage,
};

static struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};


extern void tcp_init(void);
extern void tcp_v4_init(struct net_proto_family *);

/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 */
static struct inet_protosw inetsw_array[] =
{
        {
                .type =       SOCK_STREAM,
                .protocol =   IPPROTO_TCP,
                /*  */
                .prot =       &tcp_prot,
                .ops =        &inet_stream_ops,
                .capability = -1,
                .no_check =   0,
                .flags =      INET_PROTOSW_PERMANENT,
        },

        {
                .type =       SOCK_DGRAM,
                .protocol =   IPPROTO_UDP,
                .prot =       &udp_prot,
                .ops =        &inet_dgram_ops,
                .capability = -1,
                .no_check =   UDP_CSUM_DEFAULT,
                .flags =      INET_PROTOSW_PERMANENT,
       },
        

       {
               .type =       SOCK_RAW,
               .protocol =   IPPROTO_IP,	/* wild card */
               .prot =       &raw_prot,
               .ops =        &inet_sockraw_ops,
               .capability = CAP_NET_RAW,
               .no_check =   UDP_CSUM_DEFAULT,
               .flags =      INET_PROTOSW_REUSE,
       }
};

#define INETSW_ARRAY_LEN (sizeof(inetsw_array) / sizeof(struct inet_protosw))

void inet_register_protosw(struct inet_protosw *p)
{
	struct list_head *lh;
	struct inet_protosw *answer;
	int protocol = p->protocol;
	struct list_head *last_perm;

	spin_lock_bh(&inetsw_lock);

	if (p->type >= SOCK_MAX)
		goto out_illegal;

	/* If we are trying to override a permanent protocol, bail. */
	answer = NULL;
	last_perm = &inetsw[p->type];
	list_for_each(lh, &inetsw[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);

		/* Check only the non-wild match. */
		if (INET_PROTOSW_PERMANENT & answer->flags) {
			if (protocol == answer->protocol)
				break;
			last_perm = lh;
		}

		answer = NULL;
	}
	if (answer)
		goto out_permanent;

	/* Add the new entry after the last permanent entry if any, so that
	 * the new entry does not override a permanent entry when matched with
	 * a wild-card protocol. But it is allowed to override any existing
	 * non-permanent entry.  This means that when we remove this entry, the 
	 * system automatically returns to the old behavior.
	 */
	list_add_rcu(&p->list, last_perm);
out:
	spin_unlock_bh(&inetsw_lock);

	synchronize_net();

	return;

out_permanent:
	printk(KERN_ERR "Attempt to override permanent protocol %d.\n",
	       protocol);
	goto out;

out_illegal:
	printk(KERN_ERR
	       "Ignoring attempt to register invalid socket type %d.\n",
	       p->type);
	goto out;
}

void inet_unregister_protosw(struct inet_protosw *p)
{
	if (INET_PROTOSW_PERMANENT & p->flags) {
		printk(KERN_ERR
		       "Attempt to unregister permanent protocol %d.\n",
		       p->protocol);
	} else {
		spin_lock_bh(&inetsw_lock);
		list_del_rcu(&p->list);
		spin_unlock_bh(&inetsw_lock);

		synchronize_net();
	}
}

#ifdef CONFIG_IP_MULTICAST
static struct net_protocol igmp_protocol = {
	.handler =	igmp_rcv,
};
#endif

static struct net_protocol tcp_protocol = {
	.handler =	tcp_v4_rcv,
	.err_handler =	tcp_v4_err,
	.no_policy =	1,
};

static struct net_protocol udp_protocol = {
	.handler =	udp_rcv,
	.err_handler =	udp_err,
	.no_policy =	1,
};

static struct net_protocol icmp_protocol = {
	.handler =	icmp_rcv,
};

static int __init init_ipv4_mibs(void)
{
	net_statistics[0] = alloc_percpu(struct linux_mib);
	net_statistics[1] = alloc_percpu(struct linux_mib);
	/**
	 * ����IPЭ��ͳ��������
	 */
	ip_statistics[0] = alloc_percpu(struct ipstats_mib);
	ip_statistics[1] = alloc_percpu(struct ipstats_mib);
	icmp_statistics[0] = alloc_percpu(struct icmp_mib);
	icmp_statistics[1] = alloc_percpu(struct icmp_mib);
	tcp_statistics[0] = alloc_percpu(struct tcp_mib);
	tcp_statistics[1] = alloc_percpu(struct tcp_mib);
	udp_statistics[0] = alloc_percpu(struct udp_mib);
	udp_statistics[1] = alloc_percpu(struct udp_mib);
	if (!
	    (net_statistics[0] && net_statistics[1] && ip_statistics[0]
	     && ip_statistics[1] && tcp_statistics[0] && tcp_statistics[1]
	     && udp_statistics[0] && udp_statistics[1]))
		return -ENOMEM;

	(void) tcp_mib_init();

	return 0;
}

static int ipv4_proc_init(void);
extern void ipfrag_init(void);

static int __init inet_init(void)
{
	struct sk_buff *dummy_skb;
	struct inet_protosw *q;
	struct list_head *r;
	int rc = -EINVAL;

	if (sizeof(struct inet_skb_parm) > sizeof(dummy_skb->cb)) {
		printk(KERN_CRIT "%s: panic\n", __FUNCTION__);
		goto out;
	}

	rc = sk_alloc_slab(&tcp_prot, "tcp_sock");
	if (rc) {
		sk_alloc_slab_error(&tcp_prot);
		goto out;
	}
	rc = sk_alloc_slab(&udp_prot, "udp_sock");
	if (rc) {
		sk_alloc_slab_error(&udp_prot);
		goto out_tcp_free_slab;
	}
	rc = sk_alloc_slab(&raw_prot, "raw_sock");
	if (rc) {
		sk_alloc_slab_error(&raw_prot);
		goto out_udp_free_slab;
	}

	/*
	 *	Tell SOCKET that we are alive... 
	 */

  	(void)sock_register(&inet_family_ops);

	/*
	 *	Add all the base protocols.
	 */

	if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add ICMP protocol\n");
	if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add UDP protocol\n");
	if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add TCP protocol\n");
#ifdef CONFIG_IP_MULTICAST
	if (inet_add_protocol(&igmp_protocol, IPPROTO_IGMP) < 0)
		printk(KERN_CRIT "inet_init: Cannot add IGMP protocol\n");
#endif

	/* Register the socket-side information for inet_create. */
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		inet_register_protosw(q);

	/*
	 *	Set the ARP module up
	 */

	arp_init();

  	/*
  	 *	Set the IP module up
  	 */

	ip_init();

	tcp_v4_init(&inet_family_ops);

	/* Setup TCP slab cache for open requests. */
	tcp_init();


	/*
	 *	Set the ICMP layer up
	 */

	icmp_init(&inet_family_ops);

	/*
	 *	Initialise the multicast router
	 */
#if defined(CONFIG_IP_MROUTE)
	ip_mr_init();
#endif
	/*
	 *	Initialise per-cpu ipv4 mibs
	 */ 

	if(init_ipv4_mibs())
		printk(KERN_CRIT "inet_init: Cannot init ipv4 mibs\n"); ;
	
	ipv4_proc_init();

	ipfrag_init();

	rc = 0;
out:
	return rc;
out_tcp_free_slab:
	sk_free_slab(&tcp_prot);
out_udp_free_slab:
	sk_free_slab(&udp_prot);
	goto out;
}

module_init(inet_init);

/* ------------------------------------------------------------------------ */

#ifdef CONFIG_PROC_FS
extern int  fib_proc_init(void);
extern void fib_proc_exit(void);
extern int  ip_misc_proc_init(void);
extern int  raw_proc_init(void);
extern void raw_proc_exit(void);
extern int  tcp4_proc_init(void);
extern void tcp4_proc_exit(void);
extern int  udp4_proc_init(void);
extern void udp4_proc_exit(void);

static int __init ipv4_proc_init(void)
{
	int rc = 0;

	if (raw_proc_init())
		goto out_raw;
	if (tcp4_proc_init())
		goto out_tcp;
	if (udp4_proc_init())
		goto out_udp;
	if (fib_proc_init())
		goto out_fib;
	if (ip_misc_proc_init())
		goto out_misc;
out:
	return rc;
out_misc:
	fib_proc_exit();
out_fib:
	udp4_proc_exit();
out_udp:
	tcp4_proc_exit();
out_tcp:
	raw_proc_exit();
out_raw:
	rc = -ENOMEM;
	goto out;
}

#else /* CONFIG_PROC_FS */
static int __init ipv4_proc_init(void)
{
	return 0;
}
#endif /* CONFIG_PROC_FS */

MODULE_ALIAS_NETPROTO(PF_INET);

EXPORT_SYMBOL(inet_accept);
EXPORT_SYMBOL(inet_bind);
EXPORT_SYMBOL(inet_dgram_connect);
EXPORT_SYMBOL(inet_dgram_ops);
EXPORT_SYMBOL(inet_getname);
EXPORT_SYMBOL(inet_ioctl);
EXPORT_SYMBOL(inet_listen);
EXPORT_SYMBOL(inet_register_protosw);
EXPORT_SYMBOL(inet_release);
EXPORT_SYMBOL(inet_sendmsg);
EXPORT_SYMBOL(inet_shutdown);
EXPORT_SYMBOL(inet_sock_destruct);
EXPORT_SYMBOL(inet_stream_connect);
EXPORT_SYMBOL(inet_stream_ops);
EXPORT_SYMBOL(inet_unregister_protosw);
EXPORT_SYMBOL(net_statistics);

#ifdef INET_REFCNT_DEBUG
EXPORT_SYMBOL(inet_sock_nr);
#endif
