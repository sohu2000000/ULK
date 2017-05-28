/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_input.c,v 1.10 2001/12/24 04:50:20 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

const unsigned char bridge_ula[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static int br_pass_frame_up_finish(struct sk_buff *skb)
{
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
	netif_rx(skb);

	return 0;
}

/**
 * �������豸����֡ʱ��������ݰ���Ŀ���ַ�Ǳ��ص�ַ�����������豸���ڻ���ģʽ������Ҫ�����ݰ����͵�����Э��ջ��
 * ����br_pass_frame_up��������Ҫ����:�����ݰ����͸�������
 */
static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev;

	/**
	 * �����豸�����յ��İ���
	 */
	br->statistics.rx_packets++;
	br->statistics.rx_bytes += skb->len;

	/**
	 * �����������豸����ʱ��devָ����հ����豸����ʱ����Ҫ���豸��Ϊ�����豸���͵�Э��ջ��
	 */
	indev = skb->dev;
	skb->dev = br->dev;

	/**
	 * �������ǽ�������������ͣ������br_pass_frame_up_finish���ϲ㷢�Ͱ���
	 * br_pass_frame_up_finish�����򵥵ĵ���netif_rx
	 */
	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL,
			br_pass_frame_up_finish);
}

/* note: already called with rcu_read_lock (preempt_disabled) */
/**
 * ���Ŵ��봦��������֡��
 */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = skb->dev->br_port;
	struct net_bridge *br = p->br;
	struct net_bridge_fdb_entry *dst;
	int passedup = 0;

	/**
	 * �����豸(�������Ŷ˿����ڵ��豸)���ڻ���ģʽ����Ҫ�������ϲ㷢�Ͱ���
	 */
	if (br->dev->flags & IFF_PROMISC) {
		struct sk_buff *skb2;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 != NULL) {
			passedup = 1;
			br_pass_frame_up(br, skb2);
		}
	}

	/**
	 * �㲥������Ҫ�����ж˿�ת����
	 */
	if (dest[0] & 1) {
		/**
		 * ����һ��flood���͡�
		 */
		br_flood_forward(br, skb, !passedup);
		/**
		 * ��Ҫ�����ϲ��������ݰ���
		 */
		if (!passedup)
			br_pass_frame_up(br, skb);
		goto out;
	}

	/**
	 * ��ת�����ݿ�������Ŀ���ַ��
	 */
	dst = __br_fdb_get(br, dest);
	/**
	 * Ŀ���ַ�Ǳ�����ַ��
	 */
	if (dst != NULL && dst->is_local) {
		/**
		 * �����û�����ͣ������ͣ�����ɾ������
		 */
		if (!passedup)
			br_pass_frame_up(br, skb);
		else
			kfree_skb(skb);
		goto out;
	}

	/**
	 * Ŀ���ַ��ת�����ݿ��У���ͨ��Ŀ��˿�ת������
	 */
	if (dst != NULL) {
		br_forward(dst->dst, skb);
		goto out;
	}

	/**
	 * Ŀ���ַ��û����ת�����ݿ��У�ͨ�����ж˿ڷ���һ�°�����flood�籩��
	 */
	br_flood_forward(br, skb, 0);

out:
	return 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return 0 if *pskb should be processed furthur
 *	  1 if *pskb is handled
 * note: already called with rcu_read_lock (preempt_disabled) 
 */
/**
 * ���Ŵ��봦����֡
 */
int br_handle_frame(struct net_bridge_port *p, struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	/**
	 * �κ��ڽ�ֹ�Ķ˿����յ���֡����������
	 */
	if (p->state == BR_STATE_DISABLED)
		goto err;

	/**
	 * ԴMAC��ַ�Ƕಥ��ַ��������
	 */
	if (eth_hdr(skb)->h_source[0] & 1)
		goto err;

	/**
	 * BR_STATE_LEARNING��BR_STATE_FORWARDING����״̬����Ҫ���е�ַѧϰ��
	 */
	if (p->state == BR_STATE_LEARNING ||
	    p->state == BR_STATE_FORWARDING)
		br_fdb_insert(p->br, p, eth_hdr(skb)->h_source, 0);

	if (p->br->stp_enabled &&/* ����STP֧�� */
	    !memcmp(dest, bridge_ula, 5) &&/* Ŀ���ַ�Ǵ�01:80:C2:00:00:00��01:80:C2:00:00:FF�ڵ�L2��㲥��ַ�����Ǳ�IEEE��������׼Э�顣׼ȷ��˵����һ����ַ01:80:C2:00:00:00������802.1D STP������BPDU��TCN BPDU�����͵������ַ�� */
	    !(dest[5] & 0xF0)) {
		if (!dest[5]) {/* Ŀ���ַ�Ƿ���STP�ಥ��ַ�� */
			NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev, 
				NULL, br_stp_handle_bpdu);/* ���netfilter���ܣ������br_stp_handle_bpdu����BPDU�� */
			return 1;
		}
	}
	/**
	 * ����BPDU������û�п���STP���ܡ�
	 */
	else if (p->state == BR_STATE_FORWARDING) {/* �˿ڴ��ڼ���״̬����Ҫ����֡ת���� */
		/**
		 * L2��ķ���ǽ���ܡ�ebt����Թ��˲������κ����͵�֡��
		 * ����һ����������ͬʱ���ó����Ŷ˿ں�IP�ӿڣ���ˣ���Ҫȷ���ð�Ӧ�������Ż���·�ɻ�����
		 */
		if (br_should_route_hook) {
			if (br_should_route_hook(pskb)) 
				return 0;
			/**
			 * br_should_route_hook�����޸�skb������������þֲ������������ȷ�������͡�
			 */
			skb = *pskb;
			dest = eth_hdr(skb)->h_dest;
		}

		/**
		 * ����Ŀ�ĵ�ַ������豸��MAC��ַ��ȣ������������İ���
		 */
		if (!memcmp(p->br->dev->dev_addr, dest, ETH_ALEN))
			skb->pkt_type = PACKET_HOST;

		/**
		 * ��br_handle_frame_finish������յ���֡��
		 */
		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL,
			br_handle_frame_finish);
		return 1;
	}

err:
	kfree_skb(skb);
	return 1;
}
