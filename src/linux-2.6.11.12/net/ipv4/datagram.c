/*
 *	common UDP/RAW code
 *	Linux INET implementation
 *
 * Authors:
 * 	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either version
 * 	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/route.h>

/* connect���ӵ�UDP�����ʵ�� */
int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	struct rtable *rt;
	u32 saddr;
	int oif;
	int err;

	
	if (addr_len < sizeof(*usin))/* �������Ƿ���Ч���������ȡ���ַ�� */
	  	return -EINVAL;

	if (usin->sin_family != AF_INET) 
	  	return -EAFNOSUPPORT;

	sk_dst_reset(sk);/* ������ƿ���ܴ�������ݣ������Ҫ��·�ɻ������ */

	oif = sk->sk_bound_dev_if;
	saddr = inet->saddr;
	if (MULTICAST(usin->sin_addr.s_addr)) {/* Ŀ�ĵ�ַ�Ƕಥ��ַ */
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	/* ��ѯ���·�� */
	err = ip_route_connect(&rt, usin->sin_addr.s_addr, saddr,
			       RT_CONN_FLAGS(sk), oif,
			       sk->sk_protocol,
			       inet->sport, usin->sin_port, sk);
	if (err)
		return err;
	/* Ŀ�ĵ�ַ�ǹ㲥��ַ�����׽ӿڲ�֧�ֹ㲥���򷵻ش��� */
	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		return -EACCES;
	}
	/* ����ѯ�õ���·�ɻ����е�Դ��ַ��Ŀ�ĵ�ַ��Ŀ�Ķ˿ڴ�����ƿ��� */
  	if (!inet->saddr)
	  	inet->saddr = rt->rt_src;	/* Update source address */
	if (!inet->rcv_saddr)
		inet->rcv_saddr = rt->rt_src;
	inet->daddr = rt->rt_dst;
	inet->dport = usin->sin_port;
	sk->sk_state = TCP_ESTABLISHED;
	inet->id = jiffies;

	/* ����Ŀ��·�ɻ��浽������ƿ��� */
	sk_dst_set(sk, &rt->u.dst);
	return(0);
}

EXPORT_SYMBOL(ip4_datagram_connect);

