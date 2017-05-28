#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <asm/page.h>		/* pgprot_t */

/* bits in vm_struct->flags */
/**
 * ��ʾʹ��ioremap()ӳ���Ӳ���豸�İ����ڴ档
 */
#define VM_IOREMAP	0x00000001	/* ioremap() and friends */
/**
 * ��ʾʹ��vmalloc()�õ���ҳ
 */
#define VM_ALLOC	0x00000002	/* vmalloc() */
/**
 * ��ʾʹ��vmap()ӳ����Ѿ��������ҳ��
 */
#define VM_MAP		0x00000004	/* vmap()ed pages */
/* bits [20..32] reserved for arch specific ioremap internals */

/**
 * �������ڴ�����������
 */
struct vm_struct {
	/**
	 * �ڴ����ڵ�һ���ڴ浥Ԫ�����Ե�ַ��
	 */
	void			*addr;
	/**
	 * �ڴ�����С��4096(�ڴ���֮��İ�ȫ���Ĵ�С)
	 */
	unsigned long		size;
	/**
	 * �������ڴ���ӳ����ڴ�����͡�
	 * VM_ALLOC��ʾʹ��vmalloc�õ���ҳ.
	 * VM_MAP��ʾʹ��vmapӳ����Ѿ��������ҳ��
	 * VM_IOREMAP��ʾʹ��ioremapӳ���Ӳ���豸�İ����ڴ档
	 */
	unsigned long		flags;
	/**
	 * ָ��nr_pages�����ָ�룬��������ָ��ҳ��������ָ����ɡ�
	 */
	struct page		**pages;
	/**
	 * �ڴ�������ҳ�ĸ�����
	 */
	unsigned int		nr_pages;
	/**
	 * һ��Ϊ0,�����ڴ��Ѿ���������ӳ��һ��Ӳ���豸IO�����ڴ档
	 */
	unsigned long		phys_addr;
	/**
	 * ָ����һ��vm_struct�ṹ��ָ�롣
	 */
	struct vm_struct	*next;
};

/*
 *	Highlevel APIs for driver use
 */
extern void *vmalloc(unsigned long size);
extern void *vmalloc_exec(unsigned long size);
extern void *vmalloc_32(unsigned long size);
extern void *__vmalloc(unsigned long size, int gfp_mask, pgprot_t prot);
extern void vfree(void *addr);

extern void *vmap(struct page **pages, unsigned int count,
			unsigned long flags, pgprot_t prot);
extern void vunmap(void *addr);
 
/*
 *	Lowlevel-APIs (not for driver use!)
 */
extern struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);
extern struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end);
extern struct vm_struct *remove_vm_area(void *addr);
extern int map_vm_area(struct vm_struct *area, pgprot_t prot,
			struct page ***pages);
extern void unmap_vm_area(struct vm_struct *area);

/*
 *	Internals.  Dont't use..
 * ��vmlist����ķ��ʿ�vmlist_lock���������ж�д����
 */
extern rwlock_t vmlist_lock;
extern struct vm_struct *vmlist;

#endif /* _LINUX_VMALLOC_H */
