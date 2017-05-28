#include <linux/highmem.h>

/**
 * ���������ں�ӳ�䡣
 */
void *kmap(struct page *page)
{
	/**
	 * kmap������˯�ߵģ���˼��˵�������жϺͿ��ӳٺ����е��á�
	 * �����ͼ���ж��е��ã���ômight_sleep�ᴥ���쳣��
	 */
	might_sleep();
	/**
	 * ���ҳ�����ڸ߶��ڴ棬�����page_addressֱ�ӷ������Ե�ַ��
	 */
	if (!PageHighMem(page))
		return page_address(page);
	/**
	 * �������kmap_high�������������ں�ӳ�䡣
	 */
	return kmap_high(page);
}

/**
 * ������ǰ��kmap�����������ں�ӳ��
 */
void kunmap(struct page *page)
{
	/**
	 * kmap��kunmap�����������ж���ʹ�á�
	 */
	if (in_interrupt())
		BUG();
	/**
	 * �����Ӧҳ�����Ͳ��Ǹ߶��ڴ棬��Ȼ��û�н����ں�ӳ�䣬Ҳ�Ͳ��õ��ñ������ˡ�
	 */
	if (!PageHighMem(page))
		return;
	/**
	 * kunmap_high����ִ��unmap����
	 */
	kunmap_high(page);
}

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the kmap code must perform a global TLB
 * invalidation when the kmap pool wraps.
 *
 * However when holding an atomic kmap is is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
/**
 * ������ʱ�ں�ӳ��
 * type��CPU��ͬȷ�����ĸ��̶�ӳ������Ե�ַӳ������ҳ��
 */
void *kmap_atomic(struct page *page, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	inc_preempt_count();
	/**
	 * �����ӳ���ҳ�����ڸ߶��ڴ棬��Ȼ�ò���ӳ�䡣ֱ�ӷ������Ե�ַ�����ˡ�
	 */
	if (!PageHighMem(page))
		return page_address(page);

	/**
	 * ͨ��type��CPUȷ�����Ե�ַ��
	 */
	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
#ifdef CONFIG_DEBUG_HIGHMEM
	if (!pte_none(*(kmap_pte-idx)))
		BUG();
#endif
	/**
	 * �����Ե�ַ��ҳ�����ӳ�䡣
	 */
	set_pte(kmap_pte-idx, mk_pte(page, kmap_prot));
	/**
	 * ��Ȼ��������ˢ��һ��TLB��Ȼ����ܷ������Ե�ַ��
	 */
	__flush_tlb_one(vaddr);

	return (void*) vaddr;
}

/**
 * �����ں���ʱӳ��
 */
void kunmap_atomic(void *kvaddr, enum km_type type)
{
#ifdef CONFIG_DEBUG_HIGHMEM
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	enum fixed_addresses idx = type + KM_TYPE_NR*smp_processor_id();

	if (vaddr < FIXADDR_START) { // FIXME
		dec_preempt_count();
		preempt_check_resched();
		return;
	}

	if (vaddr != __fix_to_virt(FIX_KMAP_BEGIN+idx))
		BUG();

	/*
	 * force other mappings to Oops if they'll try to access
	 * this pte without first remap it
	 */
	/**
	 * ȡ��ӳ�䲢ˢ��TLB
	 */
	pte_clear(kmap_pte-idx);
	__flush_tlb_one(vaddr);
#endif
	/**
	 * ������ռ���������ȵ㡣
	 */
	dec_preempt_count();
	preempt_check_resched();
}

struct page *kmap_atomic_to_page(void *ptr)
{
	unsigned long idx, vaddr = (unsigned long)ptr;
	pte_t *pte;

	if (vaddr < FIXADDR_START)
		return virt_to_page(ptr);

	idx = virt_to_fix(vaddr);
	pte = kmap_pte - (idx - FIX_KMAP_BEGIN);
	return pte_page(*pte);
}

