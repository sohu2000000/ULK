/*
 *	Device event handling
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_notify.c,v 1.2 2000/02/21 15:51:34 davem Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>

#include "br_private.h"

static int br_device_event(struct notifier_block *unused, unsigned long event, void *ptr);

struct notifier_block br_device_notifier = {
	.notifier_call = br_device_event
};

/*
 * Handle changes in state of network devices enslaved to a bridge.
 * 
 * Note: don't care about up/down if bridge itself is down, because
 *     port state is checked when bridge is brought up.
 */
/**
 * ���Ŵ���ע��������豸�¼��ص�������
 */
static int br_device_event(struct notifier_block *unused, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = dev->br_port;
	struct net_bridge *br;

	/* not a port of a bridge */
	if (p == NULL)
		return NOTIFY_DONE;

	br = p->br;

	spin_lock_bh(&br->lock);
	switch (event) {
	case NETDEV_CHANGEMTU:
		/**
		 * �����豸��MTU���޸�Ϊ���а��豸����СMTU��
		 */
		dev_set_mtu(br->dev, br_min_mtu(br));
		break;

	case NETDEV_CHANGEADDR:
		br_fdb_changeaddr(p, dev->dev_addr);
		br_stp_recalculate_bridge_id(br);
		break;

	case NETDEV_CHANGE:	/* device is up but carrier changed */
		/**
		 * ����������ص��豸������Ա����ʱ����IFF_UPû�б����ã�����ص�֪ͨ�¼������ԡ�
		 */
		if (!(br->dev->flags & IFF_UP))
			break;

		/**
		 * ���֪ͨ�¼����Ա����ڼ���ԭ��������ϵͳ������ע���ز�״̬�ı仯��
		 * ��һ�����豸ʧȥ���߼�⵽�ز�״̬ʱ(���߱��������߲���ʱ)��������Ŷ˿ڷֱ�br_stp_enable_port����br_stp_disable_port���û��߹رա�
		 */
		if (netif_carrier_ok(dev)) {
			if (p->state == BR_STATE_DISABLED)
				br_stp_enable_port(p);
		} else {
			if (p->state != BR_STATE_DISABLED)
				br_stp_disable_port(p);
		}
		break;

	case NETDEV_DOWN:
		/**
		 * ��һ�����豸������Ա����ʱ��������Ŷ˿�Ҳ���뱻��ֹ��
		 * ������br_stp_disable_port����ġ���������Ŷ˿��Ѿ��ر�ʱ�����ؽ��д˴���
		 */
		if (br->dev->flags & IFF_UP)
			br_stp_disable_port(p);
		break;

	case NETDEV_UP:
		/**
		 * ��һ�����豸������Ա��������IFF_UP�����ã�ʱ������������Ŷ˿ڴ��ڴ���״̬����������豸������ʱ��������Ŷ˿ڱ�br_stp_enabled_port������
		 */
		if (netif_carrier_ok(dev) && (br->dev->flags & IFF_UP)) 
			br_stp_enable_port(p);
		break;

	case NETDEV_UNREGISTER:
		spin_unlock_bh(&br->lock);
		/**
		 * ��һ�����豸ȡ��ע��ʱ��������Ŷ˿�Ҳ��br_del_ifɾ�������¼����������ı����½��С�
		 */
		br_del_if(br, dev);
		goto done;
	} 
	spin_unlock_bh(&br->lock);

 done:
	return NOTIFY_DONE;
}
