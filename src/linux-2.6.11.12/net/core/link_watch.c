/*
 * Linux network device link state notification
 *
 * Author:
 *     Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <asm/types.h>


enum lw_bits {
	/**
	 * �������־������ʱ��linkwatch_event������ִ�У��˱�־��linkwatch_event�Լ������
	 */
	LW_RUNNING = 0,
	/**
	 * ����lweventlist ͨ���в�ֹһ����Ԫ�أ������Ż���̬����� lw_event ���ݽṹ������������Ϊ��һ��Ԫ�ء������ں���Ҫ���˲�ֹһ����δ���¼�(�¼��ڲ�ֹһ���豸)��Ϊ����������lw_event�ṹ���������򵥵�����ͬһ���ṹ��
	 * �˱�־��ʾ��һ��Ԫ���Ƿ���á�
	 */
	LW_SE_USED
};

static unsigned long linkwatch_flags;
static unsigned long linkwatch_nextevent;

static void linkwatch_event(void *dummy);
static DECLARE_WORK(linkwatch_work, linkwatch_event, NULL);

/**
 * ����״̬�ı��¼��б�
 */
static LIST_HEAD(lweventlist);
/**
 * ����lweventlist���������
 */
static DEFINE_SPINLOCK(lweventlist_lock);

/**
 * �����豸����״̬�ı��¼���
 * lw_event�ṹ���������κ������źŴ��ݵļ���붪ʧ�Ĳ���.
 */
struct lw_event {
	/**
	 * ���ṹ���ӵ�δ������״̬�ı��¼�ȫ�ֶ��е��ֶ�lweventlist
	 */
	struct list_head list;
	/**
	 * ������net_device�ṹ��ָ��
	 */
	struct net_device *dev;
};

/* Avoid kmalloc() for most systems */
static struct lw_event singleevent;

/* Must be called with the rtnl semaphore held */
void linkwatch_run_queue(void)
{
	LIST_HEAD(head);
	struct list_head *n, *next;

	spin_lock_irq(&lweventlist_lock);
	list_splice_init(&lweventlist, &head);
	spin_unlock_irq(&lweventlist_lock);

	list_for_each_safe(n, next, &head) {
		struct lw_event *event = list_entry(n, struct lw_event, list);
		struct net_device *dev = event->dev;

		if (event == &singleevent) {
			clear_bit(LW_SE_USED, &linkwatch_flags);
		} else {
			kfree(event);
		}

		/* We are about to handle this device,
		 * so new events can be accepted
		 */
		/**
		 * ���dev->state��__LINK_STATE_LINKWATCH_PENDING��־λ
		 */
		clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);

		if (dev->flags & IFF_UP) {
			/**
			 * ����NETDEV_CHANGE֪ͨ��netdev_chain֪ͨ����
			 * ����RTM_NEWLINK֪ͨ��RTMGRP_LINK RTnetlink�顣
			 */
			netdev_state_change(dev);
		}

		dev_put(dev);
	}
}       

/**
 * ����lweventlist(����linkwatch_run_queue)�е�Ԫ�أ���ЩԪ�ذ���δ��������״̬�ı��¼���
 */
static void linkwatch_event(void *dummy)
{
	/* Limit the number of linkwatch events to one
	 * per second so that a runaway driver does not
	 * cause a storm of messages on the netlink
	 * socket
	 */	
	linkwatch_nextevent = jiffies + HZ;
	clear_bit(LW_RUNNING, &linkwatch_flags);

	rtnl_shlock();
	linkwatch_run_queue();
	rtnl_shunlock();
}


void linkwatch_fire_event(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state)) {
		unsigned long flags;
		struct lw_event *event;

		if (test_and_set_bit(LW_SE_USED, &linkwatch_flags)) {
			event = kmalloc(sizeof(struct lw_event), GFP_ATOMIC);

			if (unlikely(event == NULL)) {
				clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);
				return;
			}
		} else {
			event = &singleevent;
		}

		dev_hold(dev);
		event->dev = dev;

		spin_lock_irqsave(&lweventlist_lock, flags);
		list_add_tail(&event->list, &lweventlist);
		spin_unlock_irqrestore(&lweventlist_lock, flags);

		if (!test_and_set_bit(LW_RUNNING, &linkwatch_flags)) {
			unsigned long thisevent = jiffies;

			if (thisevent >= linkwatch_nextevent) {
				schedule_work(&linkwatch_work);
			} else {
				schedule_delayed_work(&linkwatch_work, linkwatch_nextevent - thisevent);
			}
		}
	}
}

EXPORT_SYMBOL(linkwatch_fire_event);
