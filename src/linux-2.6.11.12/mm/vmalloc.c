/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/vmalloc.h>

#include <asm/uaccess.h>
#include <asm/tlbflush.h>


/**
 * ����vmlist�������������
 */
DEFINE_RWLOCK(vmlist_lock);
/**
 * vm_struct����ĵ�һ��Ԫ�ء�
 */
struct vm_struct *vmlist;


/*
 * �ͷ�һ��PTҳ���Ӧ�ĵ�ַ�ռ��ҳ��([address,address+size] ��Χ��)
 */
static void unmap_area_pte(pmd_t *pmd, unsigned long address,
				  unsigned long size)
{
	unsigned long end;
	pte_t *pte;

	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}

    /*
     * �õ���һ��ҳ����pte
     */
	pte = pte_offset_kernel(pmd, address);
	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;

    /*
     * �������е�PTE(��PT�µ�)������ptep_get_and_clear�����ҳ��������(����PA��Present��)
     */
	do {
		pte_t page;
		page = ptep_get_and_clear(pte);
		address += PAGE_SIZE;
		pte++;
		if (pte_none(page))
			continue;
		if (pte_present(page))
			continue;
		printk(KERN_CRIT "Whee.. Swapped out page in kernel page table\n");
	} while (address < end);
}

/*
 * �ͷ�һ��PMD���Ӧ�ĵ�ַ�ռ��ҳ��([address,address+size] ��Χ��)
 */
static void unmap_area_pmd(pud_t *pud, unsigned long address,
				  unsigned long size)
{
	unsigned long end;
	pmd_t *pmd;

	if (pud_none(*pud))
		return;
	if (pud_bad(*pud)) {
		pud_ERROR(*pud);
		pud_clear(pud);
		return;
	}

    /*
     * �õ���һ��pmd
     */
	pmd = pmd_offset(pud, address);
	address &= ~PUD_MASK;
	end = address + size;
	if (end > PUD_SIZE)
		end = PUD_SIZE;

    /*
     * �������е�pmd�����unmap_area_pte���ҳ��
     */
	do {
		unmap_area_pte(pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
}

/*
 * �ͷ�һ��PUD���Ӧ�ĵ�ַ�ռ��ҳ��([address,address+size] ��Χ��)
 */
static void unmap_area_pud(pgd_t *pgd, unsigned long address,
			   unsigned long size)
{
	pud_t *pud;
	unsigned long end;

	if (pgd_none(*pgd))
		return;
	if (pgd_bad(*pgd)) {
		pgd_ERROR(*pgd);
		pgd_clear(pgd);
		return;
	}

    /*
     * �õ���һ��pud��
     */
	pud = pud_offset(pgd, address);
	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;

    /*
     * �����÷�Χ������pud������unmap_area_pmd�����ҳ��
     */
	do {
		unmap_area_pmd(pud, address, end - address);
		address = (address + PUD_SIZE) & PUD_MASK;
		pud++;
	} while (address && (address < end));
}

/*
 * ���ҳ���е�VA��PA��ӳ��
 */
static int map_area_pte(pte_t *pte, unsigned long address,
			       unsigned long size, pgprot_t prot,
			       struct page ***pages)
{
	unsigned long end;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;

	do {
		struct page *page = **pages;
		WARN_ON(!pte_none(*pte));
		if (!page)
			return -ENOMEM;

        /*�趨ҳ����*/
		set_pte(pte, mk_pte(page, prot));
		address += PAGE_SIZE;

        /*��һ��ҳ����*/
		pte++;
		(*pages)++;
	} while (address < end);
	return 0;
}

static int map_area_pmd(pmd_t *pmd, unsigned long address,
			       unsigned long size, pgprot_t prot,
			       struct page ***pages)
{
	unsigned long base, end;

	base = address & PUD_MASK;
	address &= ~PUD_MASK;
	end = address + size;
	if (end > PUD_SIZE)
		end = PUD_SIZE;

	do {
        /*ȡ��addr��Ӧ��ҳ����*/
		pte_t * pte = pte_alloc_kernel(&init_mm, pmd, base + address);
		if (!pte)
			return -ENOMEM;
        /*����ҳ���еĶ�Ӧ��ϵ*/
		if (map_area_pte(pte, address, end - address, prot, pages))
			return -ENOMEM;
        /*��һ��ҳ��*/
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);

	return 0;
}

static int map_area_pud(pud_t *pud, unsigned long address,
			       unsigned long end, pgprot_t prot,
			       struct page ***pages)
{
	do {
        /*����PMD��PUD�Ĺ�����ϵ*/
		pmd_t *pmd = pmd_alloc(&init_mm, pud, address);
		if (!pmd)
			return -ENOMEM;
        /*����PMD����ӳ���ϵ*/
		if (map_area_pmd(pmd, address, end - address, prot, pages))
			return -ENOMEM;
        /*ָ��PMD��ӳ��Ľ�β��ַ*/
		address = (address + PUD_SIZE) & PUD_MASK;
		pud++;
	} while (address && address < end);

	return 0;
}

void unmap_vm_area(struct vm_struct *area)
{
	unsigned long address = (unsigned long) area->addr;
	unsigned long end = (address + area->size);
	unsigned long next;
	pgd_t *pgd;
	int i;

    /*�õ���һ��pad��*/
	pgd = pgd_offset_k(address);
    /*����Ӳ������*/
    flush_cache_vunmap(address, end);
    /*
     * ������ַ�ռ��漰������pgd�����unmap_area_pud����ҳ��
     */
	for (i = pgd_index(address); i <= pgd_index(end-1); i++) {
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next <= address || next > end)
			next = end;
		unmap_area_pud(pgd, address, next - address);
		address = next;
	        pgd++;
	}

    /*
     * ˢ��TLB
     */
	flush_tlb_kernel_range((unsigned long) area->addr, end);
}

/**
 * �����Ե�ַ��ҳ���Ӧ����
 * area-ָ���ڴ�����vm_struct��������ָ��
 * prot-�ѷ���ҳ��ı���λ�������Ǳ���Ϊ0x63����Ӧ��present,accessed,read/write��dirty.
 * pages-ָ��һ��ָ������ı����ĵ�ַ����ָ�������ָ��ָ��ҳ��������
 */
int map_vm_area(struct vm_struct *area, pgprot_t prot, struct page ***pages)
{
	/**
	 * ���Ƚ��ڴ����Ŀ�ʼ��ĩβ�����Ե�ַ������ֲ�����address��end
	 */
	unsigned long address = (unsigned long) area->addr;
	unsigned long end = address + (area->size-PAGE_SIZE);
	unsigned long next;
	pgd_t *pgd;
	int err = 0;
	int i;

	/**
	 * ʹ��pgd_offset_k��������ں�ҳȫ��Ŀ¼�е�Ŀ¼���Ŀ¼���Ӧ���ڴ�����ʼ���Ե�ַ��
	 */
	/*
	 * ���¸�Ŀ¼��swapper_pg_dir���ں�ҳȫ��Ŀ¼�еĳ���ҳ���ϣ�
	 * ���ҳȫ��Ŀ¼�����ڴ���������pgd�ֶ���ָ�򣬶����ڴ������������init_mm����
     */
	pgd = pgd_offset_k(address);
	/**
	 * ����ں�ҳ����������
	 */
	spin_lock(&init_mm.page_table_lock);
	/**
	 * ��ѭ��Ϊÿ��ҳ����ҳ���
	 */
	for (i = pgd_index(address); i <= pgd_index(end-1); i++) {
		/**
		 * ����pud_alloc��Ϊ���ڴ�������һ��ҳ�ϼ�Ŀ¼���������������ַд���ں�ҳȫ��Ŀ¼�ĺ��ʱ��
		 * ������PGD��PUD����ϵ(addr��Ӧ����)
		 */
		pud_t *pud = pud_alloc(&init_mm, pgd, address);
		if (!pud) {
			err = -ENOMEM;
			break;
		}

        /*
         * next�Ǳ�PUD��ӳ�䷶Χ�Ľ�����ַ
         */
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next < address || next > end)
			next = end;
		/**
		 * map_area_pud����Ϊҳ�ϼ�Ŀ¼��ָ�������ҳ������Ӧ��ϵ��
		 * ����PUD����ӳ���ϵ
		 */
		if (map_area_pud(pud, address, next, prot, pages)) {
			err = -ENOMEM;
			break;
		}

		address = next;
		pgd++;
	}

	spin_unlock(&init_mm.page_table_lock);
	flush_cache_vmap((unsigned long) area->addr, end);
	return err;
}

#define IOREMAP_MAX_ORDER	(7 + PAGE_SHIFT)	/* 128 pages */

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end)
{
	struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	if (flags & VM_IOREMAP) {
		int bit = fls(size);

		if (bit > IOREMAP_MAX_ORDER)
			bit = IOREMAP_MAX_ORDER;
		else if (bit < PAGE_SHIFT)
			bit = PAGE_SHIFT;

		align = 1ul << bit;
	}
	addr = ALIGN(start, align);

	/**
	 * ����kmallocΪvm_struct���͵������������һ���ڴ�����
	 */
	area = kmalloc(sizeof(*area), GFP_KERNEL);
	if (unlikely(!area))
		return NULL;

	/*
	 * We always allocate a guard page.
	 */
	size += PAGE_SIZE;
	if (unlikely(!size)) {
		kfree (area);
		return NULL;
	}

	/**
	 * Ϊд���vmlist_lock����
	 */
	write_lock(&vmlist_lock);
	/**
	 * ɨ��vmlist�������������Ե�ַ��һ�������������ٸ���size+4096����ַ(4096�ǰ�ȫ��)
	 */
	for (p = &vmlist; (tmp = *p) != NULL ;p = &tmp->next) {
        /*
         * ��ʼ��ַaddr�����������Ѿ������vm_struct��VA��ַ�ռ��м�
         */
		if ((unsigned long)tmp->addr < addr) {
            /*
             * addr �Ѿ�������ǰһ��vm_struct�����ǵ����VA��ַ�ռ䣬��ôaddr�͸��µ���һ��vm_struct��VA��ַ�ռ������
             */
			if((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + 
					     (unsigned long)tmp->addr, align);
			continue;
		}

        /*
         * ���������������:
         *  tmp->addr >= addr 
         * Ҳ���� addr û�����������Ѿ������vm_struct��VA��ַ�ռ��м䣬����һ��vm_struct��ַ�ռ�֮ǰ
         */
		if ((size + addr) < addr)
			goto out;

        /*
         * addr+size Ҳû�����������Ѿ������vm_struct��VA��ַ�ռ��м䣬����һ��vm_struct��ַ�ռ�֮ǰ
         */
		if (size + addr <= (unsigned long)tmp->addr)
			goto found;

        /*
         * ���������� addr+size ��������һ���Ѿ������vm_struct��VA��ַ�ռ��м�
         * addr�͸��µ���һ��vm_struct��VA��ַ�ռ������
         */
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:
	/**
	 * �����������һ���������䣬�ͳ�ʼ�����������ֶ�
	 */
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	/**
	 * �ͷ����������ڴ�������ʼ��ַ��
	 */
	write_unlock(&vmlist_lock);

	return area;

out:
	/**
	 * û���ҵ������������ͷ������ͷ���ǰ�õ�����������Ȼ�󷵻�NULL��
	 */
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

/**
 *	get_vm_area  -  reserve a contingous kernel virtual area
 *
 *	@size:		size of the area
 *	@flags:		%VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 *	Search an area of @size in the kernel virtual mapping area,
 *	and reserved it for out purposes.  Returns the area descriptor
 *	on success or %NULL on failure.
 */
/**
 * �����Ե�ַVMALLOC_START��VMALLOC_END֮�����һ����������
 * size-�����������ڴ������ֽڴ�С
 * flag-ָ������������
 */
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
}

/**
 *	remove_vm_area  -  find and remove a contingous kernel virtual area
 *
 *	@addr:		base address
 *
 *	Search for the kernel VM area starting at @addr, and remove it.
 *	This function returns the found VM area, but using it is NOT safe
 *	on SMP machines.
 */
struct vm_struct *remove_vm_area(void *addr)
{
	struct vm_struct **p, *tmp;

	write_lock(&vmlist_lock);
    /*
     * ����vmlist���ҵ�addr��Ӧ��vm_struct
     */
	for (p = &vmlist ; (tmp = *p) != NULL ;p = &tmp->next) {
		 if (tmp->addr == addr)
			 goto found;
	}
	write_unlock(&vmlist_lock);
	return NULL;

found:
    /*
     * ɾ��vm_struct����Ӧ��ҳ�������
     */
	unmap_vm_area(tmp);
    /*
     * ����vm_struct��vmlist����ժ��
     */
	*p = tmp->next;
	write_unlock(&vmlist_lock);
	return tmp;
}

/**
 * ��vfree����vunmap���ã����ͷŷ�����������ڴ�����
 * addr-Ҫ�ͷŵ��ڴ�������ʼ��ַ��
 * deallocate_pages-�����ӳ���ҳ����Ҫ�ͷŵ�����ҳ�������������λ(��vfree���ñ�����ʱ)��������λ(��vunmap����ʱ)
 */
void __vunmap(void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;

	if ((PAGE_SIZE-1) & (unsigned long)addr) {
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		WARN_ON(1);
		return;
	}

	/**
	 * ����remove_vm_area�õ�vm_struct�������ĵ�ַ��
	 * ������������ڴ����е����Ե�ַ��Ӧ���ں˵�ҳ���
	 */
	area = remove_vm_area(addr);
	if (unlikely(!area)) {
		printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		WARN_ON(1);
		return;
	}

	/**
	 * ���deallocate_pages����λ��ɨ��ָ��ҳ��������area->nr_pages
	 */
	if (deallocate_pages) {
		int i;

		for (i = 0; i < area->nr_pages; i++) {
			/**
			 * ��ÿһ������Ԫ�أ�����__free_page�����ͷ�ҳ�򵽷���ҳ���������
			 */
			if (unlikely(!area->pages[i]))
				BUG();
			__free_page(area->pages[i]);
		}

		/**
		 * �ͷ�area->pages���鱾��
		 */
		if (area->nr_pages > PAGE_SIZE/sizeof(struct page *))
			vfree(area->pages);
		else
			kfree(area->pages);
	}

	/**
	 * �ͷ�vm_struct��������
	 */
	kfree(area);
	return;
}

/**
 *	vfree  -  release memory allocated by vmalloc()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr, as
 *	obtained from vmalloc(), vmalloc_32() or __vmalloc().
 *
 *	May not be called in interrupt context.
 */
/**
 * �ͷ�vmalloc����vmalloc_32�����ķ������ڴ�����
 */
void vfree(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 1);
}

EXPORT_SYMBOL(vfree);

/**
 *	vunmap  -  release virtual mapping obtained by vmap()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr,
 *	which was created from the page array passed to vmap().
 *
 *	May not be called in interrupt context.
 */
/**
 * �ͷ�vmap�������ڴ�����
 */
void vunmap(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 0);
}

EXPORT_SYMBOL(vunmap);

/**
 *	vmap  -  map an array of pages into virtually contiguous space
 *
 *	@pages:		array of page pointers
 *	@count:		number of pages to map
 *	@flags:		vm_area->flags
 *	@prot:		page protection for the mapping
 *
 *	Maps @count pages from @pages into contiguous kernel virtual
 *	space.
 */
/**
 * ����ӳ��������ڴ������Ѿ������ҳ�򡣱����ϣ��ú�������һ��ָ��ҳ��������ָ����Ϊ������
 * ����get_vm_area�õ�һ���µ�vm_struct��������Ȼ�����map_vm_area��ӳ��ҳ����˸ú�����vmalloc���ƣ����ǲ�����ҳ��
 * ��ҳ��pages�Ѿ��ں����������з�����ˣ�ֻ�ǻ�û��ӳ��VA���ѣ��������ӳ��
 */
void *vmap(struct page **pages, unsigned int count,
		unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;

	if (count > num_physpages)
		return NULL;

	area = get_vm_area((count << PAGE_SHIFT), flags);
	if (!area)
		return NULL;
	if (map_vm_area(area, prot, &pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
}

EXPORT_SYMBOL(vmap);

/**
 *	__vmalloc  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *	@gfp_mask:	flags for the page level allocator
 *	@prot:		protection mask for the allocated pages
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator with @gfp_mask flags.  Map them into contiguous
 *	kernel virtual space, using a pagetable protection of @prot.
 */
void *__vmalloc(unsigned long size, int gfp_mask, pgprot_t prot)
{
	struct vm_struct *area;
	struct page **pages;
	unsigned int nr_pages, array_size, i;

	/**
	 * ���Ƚ�����size��Ϊ4096����������
	 */
	size = PAGE_ALIGN(size);
	if (!size || (size >> PAGE_SHIFT) > num_physpages)
		return NULL;

	/**
	 * ͨ������get_vm_area������һ���µ��������������ط��������ڴ��������Ե�ַ��
	 * ��������flags�ֶα���ʼ��ΪVM_ALLOC������ζ��ͨ��ʹ��vmalloc������������ҳ�򽫱�ӳ�䵽һ�����Ե�ַ�ռ䡣
	 */
	area = get_vm_area(size, VM_ALLOC);
	if (!area)
		return NULL;

	nr_pages = size >> PAGE_SHIFT;
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	/**
	 * Ϊҳ������ָ���������ҳ��
	 */
	if (array_size > PAGE_SIZE)
		pages = __vmalloc(array_size, gfp_mask, PAGE_KERNEL);
	else
		pages = kmalloc(array_size, (gfp_mask & ~__GFP_HIGHMEM));
	area->pages = pages;
	if (!area->pages) {
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}
	memset(area->pages, 0, array_size);

	/**
	 * �ظ�����alloc_page��Ϊ�ڴ�������nr_pages��ҳ�򡣲��Ѷ�Ӧ��ҳ�������ŵ�area->pages�С�
	 * ����ʹ��area->pages��������Ϊ:ҳ���������ZONE_HIGHMEM�ڴ����������ʱ���ǲ�һ��ӳ�䵽һ�����Ե�ַ�ϡ�
	 */
	for (i = 0; i < area->nr_pages; i++) {
		area->pages[i] = alloc_page(gfp_mask);
		if (unlikely(!area->pages[i])) {
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
	}

	/**
	 * �����Ѿ��õ���һ�����������Ե�ַ�ռ䣬���ҷ�����һ���������ҳ����ӳ����Щ��ַ��
	 * ��Ҫ�޸��ں�ҳ��������߶�Ӧ����������map_vm_area�Ĺ�����
	 */
	if (map_vm_area(area, prot, &pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

EXPORT_SYMBOL(__vmalloc);

/**
 *	vmalloc  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
/**
 * ���ں˷���һ���������ڴ�����
 * size-�����������ڴ����Ĵ�С��
 */
void *vmalloc(unsigned long size)
{
       return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
}

EXPORT_SYMBOL(vmalloc);

/**
 *	vmalloc_exec  -  allocate virtually contiguous, executable memory
 *
 *	@size:		allocation size
 *
 *	Kernel-internal function to allocate enough pages to cover @size
 *	the page level allocator and map them into contiguous and
 *	executable kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */

#ifndef PAGE_KERNEL_EXEC
# define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

void *vmalloc_exec(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
}

/**
 *	vmalloc_32  -  allocate virtually contiguous memory (32bit addressable)
 *
 *	@size:		allocation size
 *
 *	Allocate enough 32bit PA addressable pages to cover @size from the
 *	page level allocator and map them into contiguous kernel virtual space.
 */
/**
 * ��vmalloc���ƣ�����ֻ��ZONE_NORMAL��ZONE_DMA�з����ڴ档
 */
void *vmalloc_32(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL);
}

EXPORT_SYMBOL(vmalloc_32);

long vread(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}
