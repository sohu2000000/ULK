#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/config.h>

struct vm_area_struct;

/*
 * GFP bitmasks..
 */
/* Zone modifiers in GFP_ZONEMASK (see linux/mmzone.h - low two bits) */
/**
 * �������ҳ����봦��ZONE_DMA���������ȼ���GFP_DMA
 */
#define __GFP_DMA	0x01
/**
 * �������ҳ����ZONE_HIGHMEM������
 */
#define __GFP_HIGHMEM	0x02

/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 */
/**
 * �����ں˶Եȴ�����ҳ��ĵ�ǰ���̽�������
 */
#define __GFP_WAIT	0x10	/* Can wait and reschedule? */
/**
 * �����ں˷��ʱ�����ҳ���
 */
#define __GFP_HIGH	0x20	/* Should access emergency pools? */
/**
 * �����ں��ڵͶ��ڴ���ִ��IO�������ͷ�ҳ��
 */
#define __GFP_IO	0x40	/* Can start physical IO? */
/**
 * �����0,�������ں�ִ���������ļ�ϵͳ�Ĳ�����
 */
#define __GFP_FS	0x80	/* Can call down to low-level FS? */
/**
 * �������ҳ����Ϊ"��"�ġ������ڸ��ٻ����С�
 */
#define __GFP_COLD	0x100	/* Cache-cold page required */
/**
 * һ���ڴ����ʧ�ܽ��������������Ϣ
 */
#define __GFP_NOWARN	0x200	/* Suppress page allocation failure warning */
/**
 * �ں������ڴ����ֱ���ɹ���
 */
#define __GFP_REPEAT	0x400	/* Retry the allocation.  Might fail */
/**
 * ��__GFP_REPEAT��ͬ
 */
#define __GFP_NOFAIL	0x800	/* Retry for ever.  Cannot fail */
/**
 * һ���ڴ����ʧ�ܺ������ԡ�
 */
#define __GFP_NORETRY	0x1000	/* Do not retry.  Might fail */
/**
 * Slab����������������slab���ٻ��档
 */
#define __GFP_NO_GROW	0x2000	/* Slab internal usage */
/**
 * ������չҳ��ҳ��
 */
#define __GFP_COMP	0x4000	/* Add compound page metadata */
/**
 * �κη��ص�ҳ����뱻����0
 */
#define __GFP_ZERO	0x8000	/* Return zeroed page on success */

#define __GFP_BITS_SHIFT 16	/* Room for 16 __GFP_FOO bits */
#define __GFP_BITS_MASK ((1 << __GFP_BITS_SHIFT) - 1)

/* if you forget to add the bitmask here kernel will crash, period */
#define GFP_LEVEL_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS| \
			__GFP_COLD|__GFP_NOWARN|__GFP_REPEAT| \
			__GFP_NOFAIL|__GFP_NORETRY|__GFP_NO_GROW|__GFP_COMP)

#define GFP_ATOMIC	(__GFP_HIGH)
#define GFP_NOIO	(__GFP_WAIT)
#define GFP_NOFS	(__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_USER	(__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_HIGHUSER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HIGHMEM)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA		__GFP_DMA


/*
 * There is only one page-allocator function, and two main namespaces to
 * it. The alloc_page*() variants return 'struct page *' and as such
 * can allocate highmem pages, the *get*page*() variants return
 * virtual kernel addresses to the allocated page(s).
 */

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAXNODES*MAX_NR_ZONES zones.
 *
 * For the normal case of non-DISCONTIGMEM systems the NODE_DATA() gets
 * optimized to &contig_page_data at compile-time.
 */

#ifndef HAVE_ARCH_FREE_PAGE
static inline void arch_free_page(struct page *page, int order) { }
#endif

extern struct page *
FASTCALL(__alloc_pages(unsigned int, unsigned int, struct zonelist *));

static inline struct page *alloc_pages_node(int nid, unsigned int gfp_mask,
						unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	return __alloc_pages(gfp_mask, order,
		NODE_DATA(nid)->node_zonelists + (gfp_mask & GFP_ZONEMASK));
}

#ifdef CONFIG_NUMA
extern struct page *alloc_pages_current(unsigned gfp_mask, unsigned order);
/**
 * ����2^order��������ҳ�������ص�һ��������ҳ���������ĵ�ַ���߷���NULL
 */
static inline struct page *
alloc_pages(unsigned int gfp_mask, unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	return alloc_pages_current(gfp_mask, order);
}
extern struct page *alloc_page_vma(unsigned gfp_mask,
			struct vm_area_struct *vma, unsigned long addr);
#else
/**
 * ����2^order��������ҳ�������ص�һ��������ҳ���������ĵ�ַ���߷���NULL
 */
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#endif
/**
 * ���ڻ��һ������ҳ��ĺ�
 * ������������ҳ���������ĵ�ַ�����ʧ�ܣ��򷵻�NULL
 */
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

extern unsigned long FASTCALL(__get_free_pages(unsigned int gfp_mask, unsigned int order));
extern unsigned long FASTCALL(get_zeroed_page(unsigned int gfp_mask));

/**
 * ���ڻ��һ������ҳ��ĺꡣ
 */
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)

/**
 * ���ڻ��������dma��ҳ��
 */
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))

extern void FASTCALL(__free_pages(struct page *page, unsigned int order));
extern void FASTCALL(free_pages(unsigned long addr, unsigned int order));
extern void FASTCALL(free_hot_page(struct page *page));
extern void FASTCALL(free_cold_page(struct page *page));

/**
 * �ͷ�pageָ���ҳ��
 */
#define __free_page(page) __free_pages((page), 0)
/**
 * �ͷ����Ե�ַaddr��Ӧ��ҳ��
 */
#define free_page(addr) free_pages((addr),0)

void page_alloc_init(void);

#endif /* __LINUX_GFP_H */
