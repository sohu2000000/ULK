/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_timer.c,v 1.88 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <net/tcp.h>

/* TCP��������ʱ����ೢ�Է���SYN��������Ĵ�������Ӧ����255.Ĭ��Ϊ5����Լ180s */
int sysctl_tcp_syn_retries = TCP_SYN_RETRIES; 
/* �������Ӷ��ڷ������ӳ���ǰ��෢�Ͷ��ٸ�SYN+ACK�Ρ���Ӧ�ô���255. */
int sysctl_tcp_synack_retries = TCP_SYNACK_RETRIES; 
/* �����һ�����ݽ��������ͱ���̽�����ʱ������Ĭ��Ϊ2h */
int sysctl_tcp_keepalive_time = TCP_KEEPALIVE_TIME;
/* ̽�����������һ����������Ϊ�����Ѿ��Ͽ� */
int sysctl_tcp_keepalive_probes = TCP_KEEPALIVE_PROBES;
/* TCP����̽����Ϣ�ķ��ͼ����Ĭ��Ϊ75s,�Ͽ�ʱ��ԼΪ11min */
int sysctl_tcp_keepalive_intvl = TCP_KEEPALIVE_INTVL;
/* ���ش�����������ֵʱ�����������ڶ��������������ڴ�����ƿ��е�·�ɻ�������´��ش�ʱ����·��ѡ�񣬴�Լ3s-8min */
int sysctl_tcp_retries1 = TCP_RETR1;
/* ������ʱ�������Է���TCP�λ�ʱ�ش�ʱ����ȷ���Ͽ�����֮ǰ���ԵĴ�����Ĭ��Ϊ15�Σ�Լ13-30���ӣ���ֵ�������100s */
int sysctl_tcp_retries2 = TCP_RETR2;
/* ��ȷ�������쳣�����رձ���TCP֮ǰ��������ԵĴ�����Ĭ��ֵΪ7��ʾ50s-16min�� */
int sysctl_tcp_orphan_retries;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

#ifdef TCP_DEBUG
const char tcp_timer_bug_msg[] = KERN_DEBUG "tcpbug: unknown timer value\n";
#endif

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies 
 * to optimize.
 */
/* ��ʼ��������ƿ��еĶ�ʱ�� */
void tcp_init_xmit_timers(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	init_timer(&tp->retransmit_timer);
	tp->retransmit_timer.function=&tcp_write_timer;
	tp->retransmit_timer.data = (unsigned long) sk;
	tp->pending = 0;

	init_timer(&tp->delack_timer);
	tp->delack_timer.function=&tcp_delack_timer;
	tp->delack_timer.data = (unsigned long) sk;
	tp->ack.pending = 0;

	init_timer(&sk->sk_timer);
	sk->sk_timer.function	= &tcp_keepalive_timer;
	sk->sk_timer.data	= (unsigned long)sk;
}

void tcp_clear_xmit_timers(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->pending = 0;
	sk_stop_timer(sk, &tp->retransmit_timer);

	tp->ack.pending = 0;
	tp->ack.blocked = 0;
	sk_stop_timer(sk, &tp->delack_timer);

	sk_stop_timer(sk, &sk->sk_timer);
}

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criterium is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int orphans = atomic_read(&tcp_orphan_count);

	/* If peer does not open window for long time, or did not transmit 
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		orphans <<= 1;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		orphans <<= 1;

	if (orphans >= sysctl_tcp_max_orphans ||
	    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
	     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

/* A write timeout has occurred. Process the after effects. */
/* �ش������󣬼�⵱ǰ��Դʹ����� */
static int tcp_write_timeout(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int retry_until;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {/* ���ӽ׶� */
		if (tp->retransmits)/* ���ʹ�õ�·�ɻ����� */
			dst_negative_advice(&sk->sk_dst_cache);
		retry_until = tp->syn_retries ? : sysctl_tcp_syn_retries;
	} else {
		if (tp->retransmits >= sysctl_tcp_retries1) {/* �ش���������3�Σ�����Ҫ���кڶ���� */
			/* NOTE. draft-ietf-tcpimpl-pmtud-01.txt requires pmtu black
			   hole detection. :-(

			   It is place to make it. It is not made. I do not want
			   to make it. It is disguisting. It does not work in any
			   case. Let me to cite the same draft, which requires for
			   us to implement this:

   "The one security concern raised by this memo is that ICMP black holes
   are often caused by over-zealous security administrators who block
   all ICMP messages.  It is vitally important that those who design and
   deploy security systems understand the impact of strict filtering on
   upper-layer protocols.  The safest web site in the world is worthless
   if most TCP implementations cannot transfer data from it.  It would
   be far nicer to have all of the black holes fixed rather than fixing
   all of the TCP implementations."

                           Golden words :-).
		   */

			dst_negative_advice(&sk->sk_dst_cache);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {/* �׽ӿ��Ѿ��Ͽ��������ر� */
			int alive = (tp->rto < TCP_RTO_MAX);
 
			retry_until = tcp_orphan_retries(sk, alive);

			/* �¶��׽ӿ������ﵽ���ֵ�����ߵ�ǰ�Ѿ�ʹ�õ��ڴ�ﵽӲ������ʱ����Ҫ�����ر��׽ӿ� */
			if (tcp_out_of_resources(sk, alive || tp->retransmits < retry_until))
				return 1;
		}
	}

	if (tp->retransmits >= retry_until) {/* �ﵽ�ش����ޣ�����ر��׽ӿڲ�������Ӧ���� */
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/* ��ʱȷ�϶�ʱ������ */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct tcp_sock *tp = tcp_sk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* ������ƿ��Ѿ����û��������������ʱ���������� */
		/* Try again later. */
		/* ���ack������ */
		tp->ack.blocked = 1;
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKLOCKED);
		/* �������ö�ʱ����ʱʱ�� */
		sk_reset_timer(sk, &tp->delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

	sk_stream_mem_reclaim(sk);/* ?? */

	/* �����Ѿ��رգ�����û��������ʱ����ACK��ʱ�������˳� */
	if (sk->sk_state == TCP_CLOSE || !(tp->ack.pending & TCP_ACK_TIMER))
		goto out;

	if (time_after(tp->ack.timeout, jiffies)) {/* ��ʱʱ��δ������λ��ʱ�����˳� */
		sk_reset_timer(sk, &tp->delack_timer, tp->ack.timeout);
		goto out;
	}
	/* ȥ��TCP_ACK_TIMER */
	tp->ack.pending &= ~TCP_ACK_TIMER;

	if (skb_queue_len(&tp->ucopy.prequeue)) {/* prequeue���в�Ϊ�� */
		struct sk_buff *skb;

		NET_ADD_STATS_BH(LINUX_MIB_TCPSCHEDULERFAILED, 
				 skb_queue_len(&tp->ucopy.prequeue));

		/* ͨ��sk_backlog_rcv��������е�SKB */
		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk->sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

	if (tcp_ack_scheduled(tp)) {/* ��Ҫ����ACK */
		if (!tp->ack.pingpong) {/* �ڷ���ACKǰ���뿪pingpongģʽ���������趨��ʱȷ�Ϲ���ֵ�� */
			/* Delayed ACK missed: inflate ATO. */
			tp->ack.ato = min(tp->ack.ato << 1, tp->rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			tp->ack.pingpong = 0;
			tp->ack.ato = TCP_ATO_MIN;
		}
		/* ����ACK */
		tcp_send_ack(sk);
		NET_INC_STATS_BH(LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* ������ʱ�������Զ�ͨ����մ���Ϊ0����ֹTCP������������ʱ�趨 */
static void tcp_probe_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	/**
	 * �з��ͳ�ȥ����δ��ȷ�ϵĶΣ����߷��Ͷ��л��д����͵ĶΣ����÷���̽��Ρ�
	 */
	if (tp->packets_out || !sk->sk_send_head) {
		tp->probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;/* �Ͽ�����ǰ��������ʱ������TCP�ε���Ŀ���� */

	if (sock_flag(sk, SOCK_DEAD)) {/* �����Ѿ��Ͽ����׽ӿڼ����ر� */
		int alive = ((tp->rto<<tp->backoff) < TCP_RTO_MAX);

 		/* �ر�����ǰ�����Դ����� */
		max_probes = tcp_orphan_retries(sk, alive);

		/* �ͷ���Դ������׽ӿ����ͷŹ����б��رգ��Ͳ��ط���̽����ˡ� */
		if (tcp_out_of_resources(sk, alive || tp->probes_out <= max_probes))
			return;
	}

	if (tp->probes_out > max_probes) {/* ������͵�̽�����Ŀ�ﵽ���ޣ����ʹ��󱨸沢�رսӿ� */
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk);/* ����̽��� */
	}
}

/*
 *	The TCP retransmit timer.
 */
/* �ش���ʱ�� */
static void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->packets_out)/* ���з��͵Ķζ��õ���ȷ�ϣ�����Ҫ�ش����� */
		goto out;

	BUG_TRAP(!skb_queue_empty(&sk->sk_write_queue));

	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&/* ���ʹ����Ѿ��رգ��׿�û�йر� */
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {/* TCP�������ӹ��� */
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		if (net_ratelimit()) {
			struct inet_sock *inet = inet_sk(sk);
			printk(KERN_DEBUG "TCP: Treason uncloaked! Peer %u.%u.%u.%u:%u/%u shrinks window %u:%u. Repaired.\n",
			       NIPQUAD(inet->daddr), htons(inet->dport),
			       inet->num, tp->snd_una, tp->snd_nxt);
		}
#endif
		/* ����120sû���յ����� */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			/* ������󲢹ر��׿ڲ����� */
			tcp_write_err(sk);
			goto out;
		}
		/* ����ӵ�����Ƶ�LOSS״̬ */
		tcp_enter_loss(sk, 0);
		/* ���´����ش������е�һ���� */
		tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue));
		/* ���ڷ������ش��������Ҫ����·�ɻ��棬��������� */
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	/**
	 * �ش���������⵱ǰ����Դʹ��������ش��Ĵ�����
	 * ����ش������ﵽ���ޣ�����Ҫ�������ǿ�йر��׽ӿڡ�
	 * ���ֻ��ʹ����Դ�ﵽʹ�����ޣ��򲻽����ش���
	 */
	if (tcp_write_timeout(sk))
		goto out;

	if (tp->retransmits == 0) {/* �ش�����Ϊ0��˵���ս����ش��׶Σ�����ӵ��״̬��������ͳ�� */
		if (tp->ca_state == TCP_CA_Disorder || tp->ca_state == TCP_CA_Recovery) {
			if (tp->rx_opt.sack_ok) {
				if (tp->ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKRECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPSACKFAILURES);
			} else {
				if (tp->ca_state == TCP_CA_Recovery)
					NET_INC_STATS_BH(LINUX_MIB_TCPRENORECOVERYFAIL);
				else
					NET_INC_STATS_BH(LINUX_MIB_TCPRENOFAILURES);
			}
		} else if (tp->ca_state == TCP_CA_Loss) {
			NET_INC_STATS_BH(LINUX_MIB_TCPLOSSFAILURES);
		} else {
			NET_INC_STATS_BH(LINUX_MIB_TCPTIMEOUTS);
		}
	}

	if (tcp_use_frto(sk)) {/* ������FRTO */
		tcp_enter_frto(sk);
	} else {
		tcp_enter_loss(sk, 0);/* ���볣���RTO�������ش��ָ� */
	}

	/* ��������ش������ϵ�һ��SKBʧ�ܣ���λ�ش���ʱ�����ȴ��´��ش� */
	if (tcp_retransmit_skb(sk, skb_peek(&sk->sk_write_queue)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!tp->retransmits)
			tp->retransmits=1;
		tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS,
				     min(tp->rto, TCP_RESOURCE_PROBE_INTERVAL));
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	/* ���ͳɹ��󣬵���ָ���˱��㷨ָ�����ۼ��ش����� */
	tp->backoff++;
	tp->retransmits++;

out_reset_timer:
	/* ����ش������賬ʱʱ�䣬Ȼ��λ�ش���ʱ���� */
	tp->rto = min(tp->rto << 1, TCP_RTO_MAX);
	tcp_reset_xmit_timer(sk, TCP_TIME_RETRANS, tp->rto);
	if (tp->retransmits > sysctl_tcp_retries1)
		__sk_dst_reset(sk);

out:;
}

/* TCP�ش���ʱ�����ڷ�������ʱ�趨���䳬ʱʱ���Ƕ�̬����ģ�ȡ��������ʱ�估�ش����� */
static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock*)data;
	struct tcp_sock *tp = tcp_sk(sk);
	int event;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* ���ƿ鱻�û�̬�������� */
		/* Try again later */
		/* �������ö�ʱ����ʱʱ�� */
		sk_reset_timer(sk, &tp->retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}

	/* ���TCP״̬�Ѿ��رգ�����û�й�����¼����򷵻� */
	if (sk->sk_state == TCP_CLOSE || !tp->pending)
		goto out;

	/* �����û�е��ﳬʱʱ�䣬�����账�� */
	if (time_after(tp->timeout, jiffies)) {
		/* �������ö�ʱ�����´γ�ʱʱ�� */
		sk_reset_timer(sk, &tp->retransmit_timer, tp->timeout);
		goto out;
	}

	/* �ش���ʱ���ͳ�����ʱ������ʹ�ñ���ʱ������˸��ݹ����¼��жϵ����Ǻ��¼� */
	event = tp->pending;
	tp->pending = 0;

	switch (event) {
	case TCP_TIME_RETRANS:/* �ش��¼� */
		tcp_retransmit_timer(sk);
		break;
	case TCP_TIME_PROBE0:/* �����¼� */
		tcp_probe_timer(sk);
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_stream_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */
/* ���Ӷ�ʱ�������� */
static void tcp_synack_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_listen_opt *lopt = tp->listen_opt;
	/* �ط�syn+ack���� */
	int max_retries = tp->syn_retries ? : sysctl_tcp_synack_retries;
	/* �����ϣ�����������Ӷ࣬�����Դ���ҲԽ�࣬�����������Է�ֵ */
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct open_request **reqp, *req;
	int i, budget;

	/* �������������ɢ�б�û�н��������߻�û�д������ӹ����е�����飬��ֱ�ӷ��� */
	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 3 seconds, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {/* �����������Ѿ�������������������һ�룬�������ֵ */
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {/* ��ֵ�������1 */
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

	if (tp->defer_accept)/* �ӳ�Ӧ�������£����Դ�����һ�� */
		max_retries = tp->defer_accept;

	/* ����Ҫ���İ����Ӷ��и������õ�Ԥ��ֵ�����ڰ����Ӷ��н϶࣬������ȫ����� */
	budget = 2*(TCP_SYNQ_HSIZE/(TCP_TIMEOUT_INIT/TCP_SYNQ_INTERVAL));
	i = lopt->clock_hand;/* ���ϴμ���������ʼ�������Ӷ��� */

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {/* ������ϣͰ�еİ����� */
			if (time_after_eq(now, req->expires)) {/* ��ǰ������Ѿ���ʱ */
				if ((req->retrans < thresh ||/* ����������Դ�����û�г�����ֵ  */
				     (req->acked && req->retrans < max_retries))/* �Ѿ����յ�ack�źţ���������ԭ�����δ���� */
				    && !req->class->rtx_syn_ack(sk, req, NULL)) {
					unsigned long timeo;

					if (req->retrans++ == 0)
						lopt->qlen_young--;
					/* �����ش���ʱֵ */
					timeo = min((TCP_TIMEOUT_INIT << req->retrans),
						    TCP_RTO_MAX);
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				/* �ش���������ָ��ֵ��ȡ�����������󣬲���������������ɢ�б���ɾ�� */
				write_lock(&tp->syn_wait_lock);
				*reqp = req->dl_next;
				write_unlock(&tp->syn_wait_lock);
				lopt->qlen--;
				if (req->retrans == 0)
					lopt->qlen_young--;
				tcp_openreq_free(req);
				continue;
			}
			reqp = &req->dl_next;
		}

		/* ȡ��һ��Ͱ���д��� */
		i = (i+1)&(TCP_SYNQ_HSIZE-1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen)/* �������ɢ�б��л���δ������ӵ�����飬���ٴ�������ʱ�� */
		tcp_reset_keepalive_timer(sk, TCP_SYNQ_INTERVAL);
}

void tcp_delete_keepalive_timer (struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

void tcp_reset_keepalive_timer (struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		tcp_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		tcp_delete_keepalive_timer(sk);
}


/**
 * ���ӽ�����ʱ�������ʱ����FIN_WAIT_2��ʱ���Ĵ�������
 */
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {/* �����û����̻�� */
		/* Try again later. */ 
		tcp_reset_keepalive_timer (sk, HZ/20);/* ���ö�ʱ�������˳� */
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {/* LISTEN״̬����ʾ���Ӷ�ʱ�� */
		tcp_synack_timer(sk);/* ���Ӷ�ʱ�� */
		goto out;
	}

	/* ����FIN_WAIT_2��ʱ�� */
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {/* ������FIN_WAIT_2״̬��ʱ����ڵ���0 */
			int tmo = tcp_fin_time(tp) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {/* ��ʱ��ʣ��ʱ�����0 */
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		/* ���Զ˷���rst��ر��׿� */
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	/* ���δ�򿪱���ܣ����������Ѿ��رգ����˳� */
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	elapsed = keepalive_time_when(tp);/* ���㳬ʱʱ�� */

	/* It is alive without keepalive 8) */
	if (tp->packets_out || sk->sk_send_head)/* ����������δȷ�ϵĶΣ����߷��Ͷ����л�����δ���͵ĶΣ����������� */
		goto resched;

	elapsed = tcp_time_stamp - tp->rcv_tstamp;/* ��������ʱ�� */

	if (elapsed >= keepalive_time_when(tp)) {/* ��������ʱ�䳬������ʱ�� */
		if ((!tp->keepalive_probes && tp->probes_out >= sysctl_tcp_keepalive_probes) ||/* δ���ñ���̽����������ѷ��ͱ���̽�����������Ĭ���� */
		     (tp->keepalive_probes && tp->probes_out >= tp->keepalive_probes)) {/* �Ѿ������˱���̽������������ѷ��ʹ����Ѿ����������õĴ��� */
			/* ���Է�����rst�� */
			tcp_send_active_reset(sk, GFP_ATOMIC);
			/* �ر���Ӧ�Ĵ�����ƿ� */
			tcp_write_err(sk);
			goto out;
		}
		if (tcp_write_wakeup(sk) <= 0) {/* ��������(����̽���)���������´α��ʱ����ʱ�� */
			tp->probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {/* ��������ʱ�仹δ�ﵽ����ĳ�������ʱ�䣬�����¼����´μ���ʱ����ʱ�� */
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	sk_stream_mem_reclaim(sk);/* ���ջ���?? */

resched:
	/* �������ñ��ʱ���´γ�ʱʱ�� */
	tcp_reset_keepalive_timer (sk, elapsed);
	goto out;

death:	
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

EXPORT_SYMBOL(tcp_clear_xmit_timers);
EXPORT_SYMBOL(tcp_delete_keepalive_timer);
EXPORT_SYMBOL(tcp_init_xmit_timers);
EXPORT_SYMBOL(tcp_reset_keepalive_timer);
