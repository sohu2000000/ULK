/*
 *  linux/arch/i386/mm/pgtable.c
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>

#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

void show_mem(void)
{
	int total = 0, reserved = 0;
	int shared = 0, cached = 0;
	int highmem = 0;
	struct page *page;
	pg_data_t *pgdat;
	unsigned long i;

	printk("Mem-info:\n");
	show_free_areas();
	printk("Free swap:       %6ldkB\n", nr_swap_pages<<(PAGE_SHIFT-10));
	for_each_pgdat(pgdat) {
		for (i = 0; i < pgdat->node_spanned_pages; ++i) {
			page = pgdat->node_mem_map + i;
			total++;
			if (PageHighMem(page))
				highmem++;
			if (PageReserved(page))
				reserved++;
			else if (PageSwapCache(page))
				cached++;
			else if (page_count(page))
				shared += page_count(page) - 1;
		}
	}
	printk("%d pages of RAM\n", total);
	printk("%d pages of HIGHMEM\n",highmem);
	printk("%d reserved pages\n",reserved);
	printk("%d pages shared\n",shared);
	printk("%d pages swap cached\n",cached);
}

/*
 * Associate a virtual page frame with a given physical page frame 
 * and protection flags for that frame.
 */ 
static void set_pte_pfn(unsigned long vaddr, unsigned long pfn, pgprot_t flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		BUG();
		return;
	}
	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud)) {
		BUG();
		return;
	}
	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		BUG();
		return;
	}
	pte = pte_offset_kernel(pmd, vaddr);
	/* <pfn,flags> stored as-is, to permit clearing entries */
	set_pte(pte, pfn_pte(pfn, flags));

	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

/*
 * Associate a large virtual page frame with a given physical page frame 
 * and protection flags for that frame. pfn is for the base of the page,
 * vaddr is what the page gets mapped to - both must be properly aligned. 
 * The pmd must already be instantiated. Assumes PAE mode.
 */ 
void set_pmd_pfn(unsigned long vaddr, unsigned long pfn, pgprot_t flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	if (vaddr & (PMD_SIZE-1)) {		/* vaddr is misaligned */
		printk ("set_pmd_pfn: vaddr misaligned\n");
		return; /* BUG(); */
	}
	if (pfn & (PTRS_PER_PTE-1)) {		/* pfn is misaligned */
		printk ("set_pmd_pfn: pfn misaligned\n");
		return; /* BUG(); */
	}
	pgd = swapper_pg_dir + pgd_index(vaddr);
	if (pgd_none(*pgd)) {
		printk ("set_pmd_pfn: pgd_none\n");
		return; /* BUG(); */
	}
	pud = pud_offset(pgd, vaddr);
	pmd = pmd_offset(pud, vaddr);
	set_pmd(pmd, pfn_pmd(pfn, flags));
	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

void __set_fixmap (enum fixed_addresses idx, unsigned long phys, pgprot_t flags)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	set_pte_pfn(address, phys >> PAGE_SHIFT, flags);
}

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	return (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
}

struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

#ifdef CONFIG_HIGHPTE
	pte = alloc_pages(GFP_KERNEL|__GFP_HIGHMEM|__GFP_REPEAT|__GFP_ZERO, 0);
#else
	pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
#endif
	return pte;
}

void pmd_ctor(void *pmd, kmem_cache_t *cache, unsigned long flags)
{
	memset(pmd, 0, PTRS_PER_PMD*sizeof(pmd_t));
}

/*
 * List of all pgd's needed for non-PAE so it can invalidate entries
 * in both cached and uncached pgd's; not needed for PAE since the
 * kernel pmd is shared. If PAE were not to share the pmd a similar
 * tactic would be needed. This is essentially codepath-based locking
 * against pageattr.c; it is the unique case in which a valid change
 * of kernel pagetables can't be lazily synchronized by vmalloc faults.
 * vmalloc faults work because attached pagetables are never freed.
 * The locking scheme was chosen on the basis of manfred's
 * recommendations and having no core impact whatsoever.
 * -- wli
 */
DEFINE_SPINLOCK(pgd_lock);
struct page *pgd_list;

static inline void pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);
	page->index = (unsigned long)pgd_list;
	if (pgd_list)
		pgd_list->private = (unsigned long)&page->index;
	pgd_list = page;
	page->private = (unsigned long)&pgd_list;
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *next, **pprev, *page = virt_to_page(pgd);
	next = (struct page *)page->index;
	pprev = (struct page **)page->private;
	*pprev = next;
	if (next)
		next->private = (unsigned long)pprev;
}

/*
 * ������Ϊpgd�����slab��ҳ���ʱ������pgd_ctor��ҳ����г�ʼ��
 * ���оͻ��swapper_pg_dir(init���̵��ں���ҳ�������)�����ݸ��Ƶ��µĽ���ҳ����ں�ҳ������
 */
void pgd_ctor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags;

	if (PTRS_PER_PMD == 1)
		spin_lock_irqsave(&pgd_lock, flags);

    /* 
     * ��swapper_pg_dir(init���̵��ں���ҳ�������)�����ݸ��Ƶ��µĽ���ҳ����ں�ҳ�����У�
     * ͨ������ֱ�����µ�pgdִ����swapper_pg_dir�е�PUD���PMD��������swapper_pg_dir�е�PMD��PUD��
     * ͨ���������֪�����û�̬ҳ�����ں���ҳ���PUD���PMD��
     * ���Կ��Կ����ں�̬���ʽ���ҳ���ʱ��(�ں˵�ַ����)��PMD��PUD����ֱ��ʹ��
     */
	memcpy((pgd_t *)pgd + USER_PTRS_PER_PGD,
			swapper_pg_dir + USER_PTRS_PER_PGD,
			(PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t)); /*��*/

    /*����PAE����������滹Ҫ�ٷ����û��ռ��PMD*/
	if (PTRS_PER_PMD > 1)
		return;

	pgd_list_add(pgd);
	spin_unlock_irqrestore(&pgd_lock, flags);
    /*����û�̬��ַ��PMD��pgd*/
	memset(pgd, 0, USER_PTRS_PER_PGD*sizeof(pgd_t));
}

/* never called when PTRS_PER_PMD > 1 */
void pgd_dtor(void *pgd, kmem_cache_t *cache, unsigned long unused)
{
	unsigned long flags; /* can be called from interrupt context */

	spin_lock_irqsave(&pgd_lock, flags);
	pgd_list_del(pgd);
	spin_unlock_irqrestore(&pgd_lock, flags);
}

/*
 * ULK:
 * Allocates a new Page Global Directory; 
 * if PAE is enabled, it also allocates the three children Page Middle Directories that map the User Mode linear addresses. 
 * The argument mm (the address of a memory descriptor) is ignored on the 80 x 86 architecture.
 */
/*
 * PUD��PMD�Ѿ��������μ�����: http://blog.csdn.net/tommy_wxie/article/details/17122923/
 * ������һ���µĽ���ʱ����ҪΪ�½��̴���һ���µ�ҳ��Ŀ¼PGD�������ں˵�ҳ��Ŀ¼swapper_pg_dir�и����ں�����ҳ��Ŀ¼�����½�����ҳ��Ŀ¼PGD����Ӧλ�ã�����������£�
 * do_fork() --> copy_mm() --> mm_init() --> pgd_alloc() --> set_pgd_fast() --> get_pgd_slow() --> memcpy(&PGD + USER_PTRS_PER_PGD, swapper_pg_dir + USER_PTRS_PER_PGD, (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t))
 * ����һ����ÿ�����̵�ҳ��Ŀ¼�ͷֳ��������֣�
 * ��һ����Ϊ���û��ռ䡱������ӳ�����������̿ռ䣨0x0000 0000��0xBFFF FFFF����3G�ֽڵ������ַ��
 * �ڶ�����Ϊ��ϵͳ�ռ䡱������ӳ�䣨0xC000 0000��0xFFFF FFFF��1G�ֽڵ������ַ��
 * ���Կ���Linuxϵͳ��ÿ�����̵�ҳ��Ŀ¼�ĵڶ���������ͬ�ģ����Դӽ��̵ĽǶ�������
 * ÿ��������4G�ֽڵ�����ռ䣬 �ϵ͵�3G�ֽ����Լ����û��ռ䣬��ߵ�1G�ֽ���Ϊ�����н����Լ��ں˹����ϵͳ�ռ䡣
 */ 
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	int i;
    /*
     * ����һ��pgd��������ѷ������һ����ҳ�棬����δ����PAE������൱���Ѿ�������PMD��PUD�Ŀռ�
     * ע�⣬��pgtable_cache_init��ע���˳�ʼ������Ϊpgd_ctor
     * pgd_ctor���swapper_pg_dir(init���̵��ں���ҳ�������)�����ݸ��Ƶ��µĽ���ҳ����ں�ҳ������
     */
	pgd_t *pgd = kmem_cache_alloc(pgd_cache, GFP_KERNEL);

    /*PTRS_PER_PMD = 1 ��ʾPAEδ���û��PAE��i386����ҪPUD��PMD�����Ƕ���pgd��Ӱ��*/
	if (PTRS_PER_PMD == 1 || !pgd)
		return pgd;

    /*���PAE���������3����Ӧ�û�̬���Ե�ַ����ҳ�м�Ŀ¼*/
	for (i = 0; i < USER_PTRS_PER_PGD; ++i) {
		pmd_t *pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);
		if (!pmd)
			goto out_oom;
		set_pgd(&pgd[i], __pgd(1 + __pa(pmd)));
	}
	return pgd;

out_oom:
	for (i--; i >= 0; i--)
		kmem_cache_free(pmd_cache, (void *)__va(pgd_val(pgd[i])-1));
	kmem_cache_free(pgd_cache, pgd);
	return NULL;
}

/*
 * ULK:
 * Releases the Page Global Directory at address pgd; 
 * if PAE is enabled, it also releases the three Page Middle Directories that map the User Mode linear addresses.
 */
void pgd_free(pgd_t *pgd)
{
	int i;

	/* in the PAE case user pgd entries are overwritten before usage */
	if (PTRS_PER_PMD > 1)
		for (i = 0; i < USER_PTRS_PER_PGD; ++i)
			kmem_cache_free(pmd_cache, (void *)__va(pgd_val(pgd[i])-1));
	/* in the non-PAE case, clear_page_range() clears user pgd entries */
	kmem_cache_free(pgd_cache, pgd);
}
