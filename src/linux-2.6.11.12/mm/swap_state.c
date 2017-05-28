/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>

#include <asm/pgtable.h>

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_list, to make sync_page look nicer, and to allow
 * future use of radix_tree tags in the swap cache.
 */
static struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

static struct backing_dev_info swap_backing_dev_info = {
	.memory_backed	= 1,	/* Does not contribute to dirty memory */
	.unplug_io_fn	= swap_unplug_io_fn,
};
 /*         
  * �������ٻ��������ҳֻ����һ��swapper_space��ַ�ռ䣬���ֻ��һ������
  * (��swapper_space.page_treeָ��)�Խ������ٻ����е�ҳ����Ѱַ��swapper_space
  * ��ַ�ռ��nrpages�ֶδ�Ž������ٻ����е�ҳ��
  */
struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= SPIN_LOCK_UNLOCKED,
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};
EXPORT_SYMBOL(swapper_space);

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
	unsigned long noent_race;
	unsigned long exist_race;
} swap_cache_info;

void show_swap_cache_info(void)
{
	printk("Swap cache: add %lu, delete %lu, find %lu/%lu, race %lu+%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total,
		swap_cache_info.noent_race, swap_cache_info.exist_race);
	printk("Free swap  = %lukB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * __add_to_swap_cache resembles add_to_page_cache on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 */
/**
 * ��add_to_swap_cache���ƣ����ǲ����ҳ�۲�������Ч�ԡ�
 */
static int __add_to_swap_cache(struct page *page,
		swp_entry_t entry, int gfp_mask)
{
	int error;

	BUG_ON(PageSwapCache(page));
	BUG_ON(PagePrivate(page));
	error = radix_tree_preload(gfp_mask);
	if (!error) {
		spin_lock_irq(&swapper_space.tree_lock);
		error = radix_tree_insert(&swapper_space.page_tree,
						entry.val, page);
		if (!error) {
            /*
             * ����ҳ������ü�����������PG_swapcache��PG_locked��־
             */
			page_cache_get(page);
			SetPageLocked(page);
			SetPageSwapCache(page);
			page->private = entry.val; /*��*/ /*�趨��page��privateΪindex(entry.val)�������������ֵ��֪����δ�SWAP���ҵ�ҳ�����ݲ�������*/
			total_swapcache_pages++;
			pagecache_acct(1);
		}
		spin_unlock_irq(&swapper_space.tree_lock);
		radix_tree_preload_end();
	}
	return error;
}

/**
 * ��ҳ���뽻�����ٻ����С�
 */
static int add_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int error;

	/**
	 * swap_duplicate�������е�ҳ���Ƿ���Ч��������ҳ�����ü�������
	 */
	if (!swap_duplicate(entry)) {
		INC_CACHE_INFO(noent_race);
		return -ENOENT;
	}
	/**
	 * __add_to_swap_cache����radix_tree_insert��ҳ������ٻ��档Ȼ������ҳ���ü�������
	 * ����PG_swapcache��PG_locked��־��λ��
	 */
	error = __add_to_swap_cache(page, entry, GFP_KERNEL);
	/*
	 * Anon pages are already on the LRU, we don't run lru_cache_add here.
	 */
	if (error) {
		swap_free(entry);
		if (error == -EEXIST)
			INC_CACHE_INFO(exist_race);
		return error;
	}
	INC_CACHE_INFO(add_total);
	return 0;
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 */
void __delete_from_swap_cache(struct page *page)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(!PageSwapCache(page));
	BUG_ON(PageWriteback(page));

	radix_tree_delete(&swapper_space.page_tree, page->private);
	page->private = 0;
	ClearPageSwapCache(page);
	total_swapcache_pages--;
	pagecache_acct(-1);
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock. 
 */
/**
 * add_to_swap�����ڽ������з���һ����ҳ�ۣ�����һ��ҳ����뽻�����ٻ��档
 */
int add_to_swap(struct page * page)
{
	swp_entry_t entry;
	int pf_flags;
	int err;

	if (!PageLocked(page))
		BUG();

	for (;;) {
		/**
		 * ����һ����ҳ�ۣ�ʧ���򷵻�0
		 */
		entry = get_swap_page();
		if (!entry.val)
			return 0;

		/* Radix-tree node allocations are performing
		 * GFP_ATOMIC allocations under PF_MEMALLOC.  
		 * They can completely exhaust the page allocator.  
		 *
		 * So PF_MEMALLOC is dropped here.  This causes the slab 
		 * allocations to fail earlier, so radix-tree nodes will 
		 * then be allocated from the mempool reserves.
		 *
		 * We're still using __GFP_HIGH for radix-tree node
		 * allocations, so some of the emergency pools are available,
		 * just not all of them.
		 */

		pf_flags = current->flags;
		current->flags &= ~PF_MEMALLOC;

		/*
		 * Add it to the swap cache and mark it dirty
		 */
		/**
		 * ��ҳ���뽻�����ٻ��档
		 */
		err = __add_to_swap_cache(page, entry, GFP_ATOMIC|__GFP_NOWARN);

		if (pf_flags & PF_MEMALLOC)
			current->flags |= PF_MEMALLOC;

		switch (err) {
		case 0:				/* Success */
			/**
			 * ��ҳ�������е�PG_update��PG_dirty��־��λ���Ӷ�ǿ��shrink_list������ҳд�����
			 */
			SetPageUptodate(page);
			SetPageDirty(page);
			INC_CACHE_INFO(add_total);
			return 1;
		case -EEXIST:
			/* Raced with "speculative" read_swap_cache_async */
			INC_CACHE_INFO(exist_race);
			swap_free(entry);
			continue;
		default:
			/* -ENOMEM radix-tree allocation failure */
			swap_free(entry);
			return 0;
		}
	}
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 */
/**
 * �ӽ������ٻ�����ɾ��ҳ�򡣱�ɾ����ҳ���ͷŵ����ϵͳ��
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;

	BUG_ON(!PageSwapCache(page));
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));
	BUG_ON(PagePrivate(page));
  
	entry.val = page->private;

	spin_lock_irq(&swapper_space.tree_lock);
	__delete_from_swap_cache(page);
	spin_unlock_irq(&swapper_space.tree_lock);

	swap_free(entry);
	page_cache_release(page);
}

/*
 * Strange swizzling function only for use by shmem_writepage
 */
int move_to_swap_cache(struct page *page, swp_entry_t entry)
{
	int err = __add_to_swap_cache(page, entry, GFP_ATOMIC);
	if (!err) {
		remove_from_page_cache(page);
		page_cache_release(page);	/* pagecache ref */
		if (!swap_duplicate(entry))
			BUG();
		SetPageDirty(page);
		INC_CACHE_INFO(add_total);
	} else if (err == -EEXIST)
		INC_CACHE_INFO(exist_race);
	return err;
}

/*
 * Strange swizzling function for shmem_getpage (and shmem_unuse)
 */
int move_from_swap_cache(struct page *page, unsigned long index,
		struct address_space *mapping)
{
	int err = add_to_page_cache(page, mapping, index, GFP_ATOMIC);
	if (!err) {
		delete_from_swap_cache(page);
		/* shift page from clean_pages to dirty_pages list */
		ClearPageDirty(page);
		set_page_dirty(page);
	}
	return err;
}

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside 
 * exclusive_swap_page() _with_ the lock. 
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !TestSetPageLocked(page)) {
		remove_exclusive_swap_page(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page. Can not do a lock_page,
 * as we are holding the page_table_lock spinlock.
 */
/**
 * ������˵�ǰ�����⣬û�������û�̬��������������Ӧ��ҳ�ۣ���ӽ������ٻ�����ɾ����ҳ�����ݼ�ҳʹ�ü�������
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
    /*�ͷ�pageҳ��*/
	page_cache_release(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
/**
 * ������˵�ǰ�����⣬û�������û�̬��������������Ӧ��ҳ�ۣ���ӽ������ٻ�����ɾ����ҳ�����ݼ�ҳʹ�ü�������
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	int chunk = 16;
	struct page **pagep = pages;

	lru_add_drain();
	while (nr) {
		int todo = min(chunk, nr);
		int i;

		for (i = 0; i < todo; i++)
			free_swap_cache(pagep[i]);
		release_pages(pagep, todo, 0); /*��*/
		pagep += todo;
		nr -= todo;
	}
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 */
/**
 * ͨ���������Ĳ���(����ҳ��ʶ��)�ڽ������ٻ����в���ҳ������ҳ�������ĵ�ַ
 * ���ҳ���ڽ������ٻ����У��ͷ���0. �ú�������radix_tree_lookup������
 * ��ָ��swapper_space.page_tree��ָ��ͻ���ҳ��ʶ����Ϊ�������ݣ��Բ�������Ҫ��ҳ
 *
 * �ڽ������ٻ����в���ҳ������ҳ�������ĵ�ַ��
 * ���ҳ���ڽ������ٻ����У��ͷ���0.
 *		entry:	����ҳ��ʶ����
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	spin_lock_irq(&swapper_space.tree_lock);
	/**
	 * swapper_space.page_tree�ǽ������ٻ���Ļ�����
	 */
	page = radix_tree_lookup(&swapper_space.page_tree, entry.val);
	if (page) {
		page_cache_get(page);
		INC_CACHE_INFO(find_success);
	}
	spin_unlock_irq(&swapper_space.tree_lock);
	INC_CACHE_INFO(find_total);
	return page;
}

/* 
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 */
/**
 * ����һ��ҳ��
 * 		entry:		����ҳ��ʶ����
 *		vma:		ָ���ҳ������������ָ�롣
 *		addr:		ҳ�����Ե�ַ��
 */
struct page *read_swap_cache_async(swp_entry_t entry,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *found_page, *new_page = NULL;
	int err;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 */
		spin_lock_irq(&swapper_space.tree_lock);
		/**
		 * ����radix_tree_lookup��swapper_space������Ѱ���ɻ���ҳ��ʶ��entry����λ�õ�ҳ��
		 */
		found_page = radix_tree_lookup(&swapper_space.page_tree,
						entry.val);
		/**
		 * �ڽ������ٻ����У����ظ�ҳ��
		 */
		if (found_page)
			page_cache_get(found_page);
		spin_unlock_irq(&swapper_space.tree_lock);
		if (found_page)
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		/**
		 * ҳû����ҳ���ٻ����У�����һ����ҳ��������ܷ�����ҳ�򣬾ͷ���0�Ա�ʾû���㹻���ڴ档
		 */
		if (!new_page) {
			new_page = alloc_page_vma(GFP_HIGHUSER, vma, addr); /*��*/
			if (!new_page)
				break;		/* Out of memory */
		}

		/*
		 * Associate the page with swap entry in the swap cache.
		 * May fail (-ENOENT) if swap entry has been freed since
		 * our caller observed it.  May fail (-EEXIST) if there
		 * is already a page associated with this entry in the
		 * swap cache: added by a racing read_swap_cache_async,
		 * or by try_to_swap_out (or shmem_writepage) re-using
		 * the just freed swap entry for an existing page.
		 * May fail (-ENOMEM) if radix-tree node allocation failed.
		 */
		/**
		 * ����ҳ����뽻�����ٻ��档Ҳ��ҳ������
		 */
		err = add_to_swap_cache(new_page, entry); /*��*/
		if (!err) {
			/*
			 * Initiate read into locked page and return.
			 */
			/**
			 * ��ҳ�����LRU�Ļ����
			 */
			lru_cache_add_active(new_page);
			/**
			 * �ӽ����������ҳ���ݡ�
			 */
			swap_readpage(NULL, new_page); /*��*/
			return new_page;
		}
	} while (err != -ENOENT && err != -ENOMEM);

	/**
	 * ���add_to_swap_cache�ڽ������ٻ������ҵ�ҳ��һ����������ǰһ������ʧ�ܡ�
	 * ���ͷŷ������ҳ��
     *
     * ��Ϊǰ���Ǹ�whileѭ�����ڵ�һ��ѭ�����·���ҳ��new_page����ҳ����뽻�����ٻ��棬
     * �ڶ���ѭ���л�ӽ������ٻ������ҵ�����found_page��¼������ʹ��new_page��
     * ���������ͷ�new_page�����ü���
	 */
	if (new_page)
		page_cache_release(new_page);
    /*
     * ����ҳ�������ĵ�ַ
     */
	return found_page;
}
