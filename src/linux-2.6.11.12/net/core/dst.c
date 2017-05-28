/*
 * net/core/dst.c	Protocol independent destination cache.
 *
 * Authors:		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>

#include <net/dst.h>

/* Locking strategy:
 * 1) Garbage collection state of dead destination cache
 *    entries is protected by dst_lock.
 * 2) GC is run only from BH context, and is the only remover
 *    of entries.
 * 3) Entries are added to the garbage list from both BH
 *    and non-BH context, so local BH disabling is needed.
 * 4) All operations modify state, so a spinlock is used.
 */
/**
 * �ȴ���ɾ����dst_entry�ṹ��ɵ�����
 * ��dst_gc_timer��ʱ������ʱ��ִ�ж�ʱ�����Ӻ�����
 * ֻ�����ü���__refcnt����0�ģ����ܱ�ֱ��ɾ���ģ�����ű�����������ڣ��Ա��ⱻֱ��ɾ�����±�����뵽�����ײ���
 */
static struct dst_entry 	*dst_garbage_list;
#if RT_CACHE_DEBUG >= 2 
static atomic_t			 dst_total = ATOMIC_INIT(0);
#endif
static DEFINE_SPINLOCK(dst_lock);

/**
 * dst_gc_timer_expires�Ƕ�ʱ���ڵ���֮ǰ�ȴ���������ȡֵ��Χ��DST_GC_MIN��DST_GC_MAX֮�䣬����ʱ�����Ӻ���dst_run_gc���ж�û�����dst_garbage_list����ʱ���ȴ�ʱ������dst_gc_timer_inc��
 * ��dst_gc_timer_inc������DST_GC_MIN��DST_GC_MAX�ķ�Χ�ڡ�
 */
static unsigned long dst_gc_timer_expires;
static unsigned long dst_gc_timer_inc = DST_GC_MAX;
static void dst_run_gc(unsigned long);
static void ___dst_free(struct dst_entry * dst);

static struct timer_list dst_gc_timer =
	TIMER_INITIALIZER(dst_run_gc, DST_GC_MIN, 0);

/**
 * ���������ն�ʱ�������Եر���dst_garbage_list��������dst_destroy��ɾ�����ü���Ϊ0�ı��
 */
static void dst_run_gc(unsigned long dummy)
{
	int    delayed = 0;
	struct dst_entry * dst, **dstp;

	/**
	 * ������ʧ�ܣ��Ӻ���
	 */
	if (!spin_trylock(&dst_lock)) {
		mod_timer(&dst_gc_timer, jiffies + HZ/10);
		return;
	}


	del_timer(&dst_gc_timer);
	dstp = &dst_garbage_list;
	while ((dst = *dstp) != NULL) {
		if (atomic_read(&dst->__refcnt)) {
			dstp = &dst->next;
			delayed++;
			continue;
		}
		*dstp = dst->next;

		/**
		 * ���ü����Ѿ����0��ɾ������
		 */
		dst = dst_destroy(dst);
		/**
		 * ���child������ĳ���ڵ㻹�����ã��򽫽ڵ��ٴι��������ȴ��´�ɾ����
		 */
		if (dst) {
			/* NOHASH and still referenced. Unless it is already
			 * on gc list, invalidate it and add to gc list.
			 *
			 * Note: this is temporary. Actually, NOHASH dst's
			 * must be obsoleted when parent is obsoleted.
			 * But we do not have state "obsoleted, but
			 * referenced by parent", so it is right.
			 */
			if (dst->obsolete > 1)
				continue;

			___dst_free(dst);
			dst->next = *dstp;
			*dstp = dst;
			dstp = &dst->next;
		}
	}
	if (!dst_garbage_list) {
		dst_gc_timer_inc = DST_GC_MAX;
		goto out;
	}
	/**
	 * û��ɾ����������DST��������ʱ����
	 */
	if ((dst_gc_timer_expires += dst_gc_timer_inc) > DST_GC_MAX)
		dst_gc_timer_expires = DST_GC_MAX;
	dst_gc_timer_inc += DST_GC_INC;
	dst_gc_timer.expires = jiffies + dst_gc_timer_expires;
#if RT_CACHE_DEBUG >= 2
	printk("dst_total: %d/%d %ld\n",
	       atomic_read(&dst_total), delayed,  dst_gc_timer_expires);
#endif
	add_timer(&dst_gc_timer);

out:
	spin_unlock(&dst_lock);
}

static int dst_discard_in(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static int dst_discard_out(struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

/**
 * ����һ��·�ɻ��������������Ļ��������ܷ���rtable(IPV4)Ҳ���ܷ���rt6_info(IPV6)��
 */
void * dst_alloc(struct dst_ops * ops)
{
	struct dst_entry * dst;

	/**
	 * ��黺�����Ƿ񳬹����ƣ�����ǣ����������չ��̡�
	 */
	if (ops->gc && atomic_read(&ops->entries) > ops->gc_thresh) {
		if (ops->gc())
			return NULL;
	}
	/**
	 * Ϊ�»���������ռ䡣
	 */
	dst = kmem_cache_alloc(ops->kmem_cachep, SLAB_ATOMIC);
	if (!dst)
		return NULL;
	/**
	 * �Ի������һЩ�ֶγ�ʼ����������Ҫ���������ֶΣ�
	 * 		rth->u.dst.input
	 * 		rth->u.dst.output
	 */
	memset(dst, 0, ops->entry_size);
	atomic_set(&dst->__refcnt, 0);
	dst->ops = ops;
	dst->lastuse = jiffies;
	dst->path = dst;
	dst->input = dst_discard_in;
	dst->output = dst_discard_out;
#if RT_CACHE_DEBUG >= 2 
	atomic_inc(&dst_total);
#endif
	atomic_inc(&ops->entries);
	return dst;
}

static void ___dst_free(struct dst_entry * dst)
{
	/* The first case (dev==NULL) is required, when
	   protocol module is unloaded.
	 */
	if (dst->dev == NULL || !(dst->dev->flags&IFF_UP)) {
		dst->input = dst_discard_in;
		dst->output = dst_discard_out;
	}
	dst->obsolete = 2;
}

void __dst_free(struct dst_entry * dst)
{
	spin_lock_bh(&dst_lock);
	___dst_free(dst);
	dst->next = dst_garbage_list;
	dst_garbage_list = dst;
	if (dst_gc_timer_inc > DST_GC_INC) {
		dst_gc_timer_inc = DST_GC_INC;
		dst_gc_timer_expires = DST_GC_MIN;
		mod_timer(&dst_gc_timer, jiffies + dst_gc_timer_expires);
	}
	spin_unlock_bh(&dst_lock);
}

struct dst_entry *dst_destroy(struct dst_entry * dst)
{
	struct dst_entry *child;
	struct neighbour *neigh;
	struct hh_cache *hh;

	smp_rmb();

again:
	neigh = dst->neighbour;
	hh = dst->hh;
	child = dst->child;

	dst->hh = NULL;
	if (hh && atomic_dec_and_test(&hh->hh_refcnt))
		kfree(hh);

	if (neigh) {
		dst->neighbour = NULL;
		neigh_release(neigh);
	}

	atomic_dec(&dst->ops->entries);

	if (dst->ops->destroy)
		dst->ops->destroy(dst);
	if (dst->dev)
		dev_put(dst->dev);
#if RT_CACHE_DEBUG >= 2 
	atomic_dec(&dst_total);
#endif
	kmem_cache_free(dst->ops->kmem_cachep, dst);

	dst = child;
	if (dst) {
		if (atomic_dec_and_test(&dst->__refcnt)) {
			/* We were real parent of this dst, so kill child. */
			if (dst->flags&DST_NOHASH)
				goto again;
		} else {
			/* Child is still referenced, return it for freeing. */
			if (dst->flags&DST_NOHASH)
				return dst;
			/* Child is still in his hash table */
		}
	}
	return NULL;
}

/* Dirty hack. We did it in 2.2 (in __dst_free),
 * we have _very_ good reasons not to repeat
 * this mistake in 2.3, but we have no choice
 * now. _It_ _is_ _explicit_ _deliberate_
 * _race_ _condition_.
 *
 * Commented and originally written by Alexey.
 */
static inline void dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			      int unregister)
{
	if (dst->ops->ifdown)
		dst->ops->ifdown(dst, dev, unregister);

	if (dev != dst->dev)
		return;

	if (!unregister) {
		/**
		 * ��Ϊ�豸Ϊdown�����Բ����ܹ�����豸����������
		 * �����dst_entry�е�input��output���򱻷ֱ�����Ϊdst_discard_in��dst_discard_out��
		 * �����������������κ�����buffer�������Ǳ�Ҫ���������֡���򵥶�������
		 */
		dst->input = dst_discard_in;
		dst->output = dst_discard_out;
	} else {
		/**
		 * ���豸��ע��ʱ���Ը��豸���������ö����뱻ɾ����
		 * dst_ifdown��dst_entry�ṹ����ص�neighbourʵ���е����豸�����ö��滻Ϊ��loopback�豸�����á�
		 */
		dst->dev = &loopback_dev;
		dev_hold(&loopback_dev);
		dev_put(dev);
		if (dst->neighbour && dst->neighbour->dev == dev) {
			dst->neighbour->dev = &loopback_dev;
			dev_put(dev);
			dev_hold(&loopback_dev);
		}
	}
}

/**
 * DST��ϵͳ�����豸�¼��Ĵ��롣
 */
static int dst_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct dst_entry *dst;

	switch (event) {
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		spin_lock_bh(&dst_lock);
		/**
		 * ������dead dst_entry�ṹ��ɵ�dst_garbage_list������ÿһ�����dst_ifdown��
		 * dst_ifdown�����һ���������ΪҪ������¼���
		 */
		for (dst = dst_garbage_list; dst; dst = dst->next) {
			dst_ifdown(dst, dev, event != NETDEV_DOWN);
		}
		spin_unlock_bh(&dst_lock);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block dst_dev_notifier = {
	.notifier_call	= dst_dev_event,
};

/**
 * ��ʼ��DSTЭ���޹�·�ɻ��档��net_dev_init���á�
 */
void __init dst_init(void)
{
	register_netdevice_notifier(&dst_dev_notifier);
}

EXPORT_SYMBOL(__dst_free);
EXPORT_SYMBOL(dst_alloc);
EXPORT_SYMBOL(dst_destroy);
