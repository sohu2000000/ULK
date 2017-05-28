/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/syscalls.h>
/*
 * This is needed for the following functions:
 *  - try_to_release_page
 *  - block_invalidatepage
 *  - generic_osync_inode
 *
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for generic_osync_inode */

#include <asm/uaccess.h>
#include <asm/mman.h>

/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_lock		(vmtruncate)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_list_lock
 *        ->swap_device_lock	(exclusive_swap_page, others)
 *          ->mapping->tree_lock
 *
 *  ->i_sem
 *    ->i_mmap_lock		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_lock
 *      ->page_table_lock	(various places, mainly in mmap.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->mmap_sem
 *    ->i_sem			(msync)
 *
 *  ->i_sem
 *    ->i_alloc_sem             (various)
 *
 *  ->inode_lock
 *    ->sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_lock
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock		(anon_vma_prepare and various)
 *
 *  ->page_table_lock
 *    ->swap_device_lock	(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone.lru_lock		(follow_page->mark_page_accessed)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 *  ->task->proc_lock
 *    ->dcache_lock		(proc_pid_lookup)
 */

/*
 * Remove a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold a write_lock on the mapping's tree_lock.
 */
/**
 * ��ҳ���ٻ�����ɾ��ҳ������
 */
void __remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	/**
	 * radix_tree_delete����ҳ�����Ӹ��ڵ㿪ʼ����������ִ��ɾ������
	 */
	radix_tree_delete(&mapping->page_tree, page->index); /*��*/
	/**
	 * ����mapping�ֶ�
	 */
	page->mapping = NULL; /*��*/
	/**
	 * ��������ҳ��nrpagesֵ��1.
	 */
	mapping->nrpages--; 
	/**
	 * �ݼ�����ҳ������
	 */
	pagecache_acct(-1);
}

/**
 * ��ҳ���ٻ�����ɾ��ҳ������
 */
void remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (unlikely(!PageLocked(page)))
		PAGE_BUG(page);
	/**
	 * ��ȡ���������жϡ�
	 */
	spin_lock_irq(&mapping->tree_lock);
	/**
	 * __remove_from_page_cache����������ɾ���ڵ㡣
	 */
	__remove_from_page_cache(page); /*��*/
	/**
	 * �ͷ��������жϡ�
	 */
	spin_unlock_irq(&mapping->tree_lock);
}

static int sync_page(void *word)
{
	struct address_space *mapping;
	struct page *page;

	page = container_of((page_flags_t *)word, struct page, flags);

	/*
	 * FIXME, fercrissake.  What is this barrier here for?
	 */
	smp_mb();
	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->sync_page)
		mapping->a_ops->sync_page(page);
	io_schedule();
	return 0;
}

/**
 * filemap_fdatawrite_range - start writeback against all of a mapping's
 * dirty pages that lie within the byte offsets <start, end>
 * @mapping: address space structure to write
 * @start: offset in bytes where the range starts
 * @end : offset in bytes where the range ends
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory * cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 */
/* ��д�ļ��ڵ�����ݵ����� */
static int __filemap_fdatawrite_range(struct address_space *mapping,
	loff_t start, loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = mapping->nrpages * 2,
		.start = start,
		.end = end,
	}; /*��*/

	if (mapping->backing_dev_info->memory_backed)
		return 0;

	ret = do_writepages(mapping, &wbc); /*��*/
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, 0, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

static int filemap_fdatawrite_range(struct address_space *mapping,
	loff_t start, loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}

/*
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

/*
 * Wait for writeback to complete against pages indexed by start->end
 * inclusive
 */
static int wait_on_page_writeback_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;
	pgoff_t index;

	if (end < start)
		return 0;

	pagevec_init(&pvec, 0);
	index = start;
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index, /*pvec ��*/
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page); /*��*/
			if (PageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	/* Check for outstanding write errors */
	if (test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;

	return ret;
}

/*
 * Write and wait upon all the pages in the passed range.  This is a "data
 * integrity" operation.  It waits upon in-flight writeout before starting and
 * waiting upon new writeout.  If there was an IO error, return it.
 *
 * We need to re-take i_sem during the generic_osync_inode list walk because
 * it is otherwise livelockable.
 */
int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (mapping->backing_dev_info->memory_backed || !count)
		return 0;
	/**
	 * ����address_space�����writepages��������mpage_writepages��������ʼ��ҳ�Ĵ��䡣
	 */
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1); /*��*/
	if (ret == 0) {
		down(&inode->i_sem);
		/**
		 * �������ڵ����صĻ�����ˢ�µ����̡�
		 */
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA); /*��*/
		up(&inode->i_sem);
	}

	/**
	 * ����ǰ����һֱ��ȫ����ˢ��ҳ��PG_writeback��־��0.
	 */
	if (ret == 0)
		ret = wait_on_page_writeback_range(mapping, start, end); /*��*/
	return ret;
}
EXPORT_SYMBOL(sync_page_range);

/*
 * Note: Holding i_sem across sync_page_range_nolock is not a good idea
 * as it forces O_SYNC writers to different parts of the same file
 * to be serialised right until io completion.
 */
int sync_page_range_nolock(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (mapping->backing_dev_info->memory_backed || !count)
		return 0;
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1);
	if (ret == 0)
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA);
	if (ret == 0)
		ret = wait_on_page_writeback_range(mapping, start, end);
	return ret;
}
EXPORT_SYMBOL(sync_page_range_nolock);

/**
 * filemap_fdatawait - walk the list of under-writeback pages of the given
 *     address space and wait for all of them.
 *
 * @mapping: address space structure to wait for
 */
/* �ȴ��ļ���д��� */
int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return wait_on_page_writeback_range(mapping, 0,
				(i_size - 1) >> PAGE_CACHE_SHIFT);
}
EXPORT_SYMBOL(filemap_fdatawait);

/* ��д�ļ� */
int filemap_write_and_wait(struct address_space *mapping)
{
	int retval = 0;

	if (mapping->nrpages) {/* �ļ����Ȳ�Ϊ0 */
		/* ��д���� */
		retval = filemap_fdatawrite(mapping); /*��*/
		if (retval == 0)
			/* �ȴ���д��� */
			retval = filemap_fdatawait(mapping); /*��*/
	}
	return retval;
}

/*
 * This function is used to add newly allocated pagecache pages:
 * the page is new, so we can just run SetPageLocked() against it.
 * The other page state flags were set by rmqueue().
 *
 * This function does not add the page to the LRU.  The caller must do that.
 */
/**
 * ��һ����ҳ�����������뵽ҳ���ٻ��档
 * �����յĲ����У�ҳ�������ĵ�ַpage��address_space����ĵ�ַmapping����ʾ�ڵ�ַ�ռ��ڵ�ҳ������ֵoffset��Ϊ���������½��ʱ��ʹ�õ��ڴ�����־gfp_mask
 */
int add_to_page_cache(struct page *page, struct address_space *mapping,
		pgoff_t offset, int gfp_mask)
{
	/**
	 * ����radix_tree_preload���������ں���ռ������һЩ�յ�radix_tree_node�ṹ����ÿCPU����radix_tree_preloads��
	 * radix_tree_node�ṹ�ķ�����slab������ٻ���radix_tree_node_cachep���
	 * ���radix_tree_node_cachepԤ���䲻�ɹ���add_to_page_cache����ֹ�����ش���-ENOMEM��
	 */
	int error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);

	/*
	 * ���radix_tree_preload �ɹ�����ڵ�
	 */
	if (error == 0) {
		/**
		 * ��ȡtree_lock������
		 * radix_tree_preload�Ѿ���ֹ���ں���ռ��
		 */
		spin_lock_irq(&mapping->tree_lock);
		/**
		 * ����radix_tree_insert�����в����½��
		 */
		error = radix_tree_insert(&mapping->page_tree, offset, page); /*��*/
		if (!error) {
			/**
			 * ����ҳ��������ʹ�ü���
			 */
			page_cache_get(page);
			/**
			 * ����ҳ���µģ�����ʹ��������Ч����������ҳ���PG_locked��־������ֹ�����ں�·�����ʸ�ҳ��
			 */
			SetPageLocked(page);
			/**
			 * ʹ��mapping ��offset ������ʼ��page
			 */
			page->mapping = mapping; /*��*/
			page->index = offset; /*��*/
			mapping->nrpages++;
			/**
			 * ���ӵ�ַ�ռ�Ļ���ҳ�ļ�������
			 */
			pagecache_acct(1);
		}
		/**
		 * �ͷ�������������radix_tree_preload_end���������ں���ռ��
		 */
		spin_unlock_irq(&mapping->tree_lock);
		radix_tree_preload_end(); /*��*/
	}
	return error;
}

EXPORT_SYMBOL(add_to_page_cache);

/**
 * ������ҳ�����������ٻ�����.��ҳ��PG_locked��־����λ.
 * ����ҳ����LRU������.
 */
int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, int gfp_mask)
{
    /**
     * ����add_to_page_cache������ҳ�����������ٻ�����.��ҳ��PG_locked��־����λ.
     */        
	int ret = add_to_page_cache(page, mapping, offset, gfp_mask); /*��*/
	if (ret == 0)
		/*
		 * ����lru_cache_add������ҳ����LRU������.
	     */
		lru_cache_add(page); /*��*/
	return ret;
}

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static inline void wake_up_page(struct page *page, int bit)
{
	__wake_up_bit(page_waitqueue(page), &page->flags, bit);
}

void fastcall wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

/**
 * unlock_page() - unlock a locked page
 *
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechananism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * The first mb is necessary to safely close the critical section opened by the
 * TestSetPageLocked(), the second mb is necessary to enforce ordering between
 * the clear_bit and the read of the waitqueue (to avoid SMP races with a
 * parallel wait_on_page_locked()).
 */
/*
 * �ں�ʹ��unlock_page������ҳ���н������������ڵȴ�������˯�ߵĽ���
 */
void fastcall unlock_page(struct page *page)
{
	smp_mb__before_clear_bit();
	if (!TestClearPageLocked(page)) /*��*/
		BUG();
	smp_mb__after_clear_bit(); 
	wake_up_page(page, PG_locked); /*��*/
}
EXPORT_SYMBOL(unlock_page);

/*
 * End writeback against a page.
 */
void end_page_writeback(struct page *page)
{
	if (!TestClearPageReclaim(page) || rotate_reclaimable_page(page)) {
		if (!test_clear_page_writeback(page))
			BUG();
	}
	smp_mb__after_clear_bit();
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/*
 * Get a lock on the page, assuming we need to sleep to get it.
 *
 * Ugly: running sync_page() in state TASK_UNINTERRUPTIBLE is scary.  If some
 * random driver's requestfn sets TASK_RUNNING, we could busywait.  However
 * chances are that on the second loop, the block layer's plug list is empty,
 * so sync_page() will then return in state TASK_UNINTERRUPTIBLE.
 */
void fastcall __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	/*
	 * ����Ѿ�������PG_locked�������ȴ����У��ѽ�������ΪTASK_UNINTERRUPTIBLE
	 * ����sync_page ������ȡ���ļ����ڿ��豸��������У�����schedule()  ����������
	 * ֱ����PG_locked ��־���㡣
	 * �ں�ʹ��unlock_page ������ҳ���н������������ڵȴ�������˯�ߵĽ���
	 */
	__wait_on_bit_lock(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

/*
 * a rather lightweight function, finding and getting a reference to a
 * hashed page atomically.
 */
/**
 * ��ҳ���ٻ���Ļ����в���ҳ
 * @mapping - ָ��address_space �����ָ��
 * @offset - ƫ����(Ҳ��ҳ����)
 */
struct page * find_get_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	/**
	 * �Ȼ�ȡ������
	 */
	spin_lock_irq(&mapping->tree_lock);
	/**
	 * radix_tree_lookup��������ӵ��ָ��ƫ�����Ļ�����Ҷ�ӽڵ㡣
	 * ����ƫ����ֵ�е�λ���δ�������ʼ�������������������ָ�룬�򷵻�NULL�����򣬷���Ҷ�ӽڵ�ĵ�ַ��
	 */
	page = radix_tree_lookup(&mapping->page_tree, offset);
	/**
	 * ����ҵ�����Ҫ��ҳ�������Ӹ�ҳ��ʹ�ü�����
	 */
	if (page)
		page_cache_get(page);
	/**
	 * �ͷŻ�������������ҳ��ַ��
	 */
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_get_page);

/*
 * Same as above, but trylock it instead of incrementing the count.
 */
/**
 * ��find_lock_page���ƣ����ǵ�������������ǰ���̡�
 */
struct page *find_trylock_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	spin_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset); /*��*/
	if (page && TestSetPageLocked(page)) /*��*/
		page = NULL;
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_trylock_page);

/**
 * find_lock_page - locate, pin and lock a pagecache page
 *
 * @mapping - the address_space to search
 * @offset - the page index
 *
 * Locates the desired pagecache page, locks it, increments its reference
 * count and returns its address.
 *
 * Returns zero if the page was not present. find_lock_page() may sleep.
 */
/**
 * ��find_get_page���ƣ��������������lock_page����ҳ��PG_locked��־��Ϊ���ǵ����߿����Ի���ķ�ʽ�������ҳ��
 */
struct page *find_lock_page(struct address_space *mapping,
				unsigned long offset)
{
	struct page *page;

	spin_lock_irq(&mapping->tree_lock);
repeat:
	page = radix_tree_lookup(&mapping->page_tree, offset); /*��*/
	if (page) {
		page_cache_get(page);
		if (TestSetPageLocked(page)) {/* �Ѿ�������������ס */
			spin_unlock_irq(&mapping->tree_lock);/* ���ͷ�������Ϊ����lock_page���ܻᱻ���ȳ��� */
			lock_page(page); /* ��סҳ�� */
			spin_lock_irq(&mapping->tree_lock);

			/* Has the page been truncated while we slept? */
			if (page->mapping != mapping || page->index != offset) {/* ȷ����˯�߹����У�ҳ��û�з����仯 */
				unlock_page(page);
				page_cache_release(page);
				goto repeat;
			}
		}
	}
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_lock_page);

/**
 * find_or_create_page - locate or add a pagecache page
 *
 * @mapping - the page's address_space
 * @index - the page's index into the mapping
 * @gfp_mask - page allocation mode
 *
 * Locates a page in the pagecache.  If the page is not present, a new page
 * is allocated using @gfp_mask and is added to the pagecache and to the VM's
 * LRU list.  The returned page is locked and has its reference count
 * incremented.
 *
 * find_or_create_page() may sleep, even if @gfp_flags specifies an atomic
 * allocation!
 *
 * find_or_create_page() returns the desired page's address, or zero on
 * memory exhaustion.
 */
/**
 * ִ��find_lock_page������Ҳ����������ҳ���ͷ���һ����ҳ���������뵽ҳ���ٻ��档
 */
struct page *find_or_create_page(struct address_space *mapping,
		unsigned long index, unsigned int gfp_mask)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_lock_page(mapping, index); /*��*/
	if (!page) { /*����Ҳ���*/
		if (!cached_page) {
			cached_page = alloc_page(gfp_mask); /*��*/
			if (!cached_page)
				return NULL;
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, gfp_mask); /*��*/
		if (!err) {
			page = cached_page;
			cached_page = NULL;
		} else if (err == -EEXIST)
			goto repeat;
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

EXPORT_SYMBOL(find_or_create_page);

/**
 * find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * find_get_pages() returns the number of pages which were found.
 */
/**
 * ��find_get_page���ƣ��������ڸ��ٻ����в���һ���������������ҳ��
 * mapping:		��mapping�Ļ����в���
 * start:		��ַ�ռ��������������ʼλ�õ�ƫ������Ҳ���ǵ�һ��Ҫ������page index
 * nr_pages:	��������ҳ���������
 * pages:		��ż�������ҳ��
 */
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	spin_lock_irq(&mapping->tree_lock);
	/**
	 * radix_tree_gang_lookupʵ�������Ĳ��Ҳ�������Ϊָ�����鸳ֵ�������ҵ���ҳ����
	 * ����һЩҳ���ܲ���ҳ���ٻ����У����Խ���л���ֿ�ȱ��ҳ���������Ƿ��ص�ҳ������ֵ�ǵ����ġ�
	 */
	ret = radix_tree_gang_lookup(&mapping->page_tree,
				(void **)pages, start, nr_pages);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	spin_unlock_irq(&mapping->tree_lock);
	return ret;
}

/*
 * Like find_get_pages, except we only return pages which are tagged with
 * `tag'.   We update *index to index the next page for the traversal.
 */
/**
 * ��find_get_pages���ƣ����Ƿ��ص�ֻ����Щ��tag������ǵ�ҳ��
 * ����������ڿ����ҵ�һ�������ڵ��������ҳ�Ƿǳ��ؼ��ġ�
 */
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	spin_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup_tag(&mapping->page_tree,
				(void **)pages, *index, nr_pages, tag);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	if (ret)
		*index = pages[ret - 1]->index + 1;
	spin_unlock_irq(&mapping->tree_lock);
	return ret;
}

/*
 * Same as grab_cache_page, but do not wait if the page is unavailable.
 * This is intended for speculative data generators, where the data can
 * be regenerated if the page couldn't be grabbed.  This routine should
 * be safe to call while holding the lock for another page.
 *
 * Clear __GFP_FS when allocating the page to avoid recursion into the fs
 * and deadlock against the caller's locked page.
 */
struct page *
grab_cache_page_nowait(struct address_space *mapping, unsigned long index)
{
	struct page *page = find_get_page(mapping, index);
	int gfp_mask;

	if (page) {
		if (!TestSetPageLocked(page))
			return page;
		page_cache_release(page);
		return NULL;
	}
	gfp_mask = mapping_gfp_mask(mapping) & ~__GFP_FS;
	page = alloc_pages(gfp_mask, 0);
	if (page && add_to_page_cache_lru(page, mapping, index, gfp_mask)) {
		page_cache_release(page);
		page = NULL;
	}
	return page;
}

EXPORT_SYMBOL(grab_cache_page_nowait);

/*
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level
 * stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 *
 * Note the struct file* is only passed for the use of readpage.  It may be
 * NULL.
 */
/**
 * �Ӵ��̶����������ҳ,�������Ǹ��Ƶ��û�̬������.��do_generic_file_read����
 */
void do_generic_mapping_read(struct address_space *mapping,
			     struct file_ra_state *_ra,
			     struct file *filp,
			     loff_t *ppos,
			     read_descriptor_t *desc,
			     read_actor_t actor)
{
	/**
	 * ��õ�ַ�ռ����������ߣ��������ڵ��������ӵ��������ļ����ݵ�ҳ�棬���ĵ�ַ�����address_space�����host�ֶ��С�
	 * ��������ļ��ǿ��豸�ļ�����ô�����߾Ͳ�����filep->f_dentry->d_inodeָ��������ڵ���󣬶���bdev�����ļ�ϵͳ�е������ڵ����
	 */
	struct inode *inode = mapping->host;
	unsigned long index;
	unsigned long end_index;
	unsigned long offset;
	unsigned long req_size;
	unsigned long next_index;
	unsigned long prev_index;
	loff_t isize;
	struct page *cached_page;
	int error;
	struct file_ra_state ra = *_ra;

	cached_page = NULL;
	/*
	 * ���ļ�ϵͳ����ϸ�ֵ�����ҳ(ÿҳ4K�ֽ�)
	 */
	/**
	 * ���ļ�ָ��*ppos������һ�������ֽ�����ҳ���߼���,����ַ�ռ��е�ҳ����,�������index������
	 */
	index = *ppos >> PAGE_CACHE_SHIFT; 
	next_index = index;
	prev_index = ra.prev_page;
	req_size = (desc->count + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	/**
	 * Ҳ�ѵ�һ�������ֽ���ҳ�ڵ�ƫ���������offset�ֲ�������.
	 */
	offset = *ppos & ~PAGE_CACHE_MASK;

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT; //end_index��ʾ���һ��ҳ���������
	/**
	 * ��ʼһ��ѭ������ȡ���������ֽڵ�����ҳ��Ҫ��ȡ���ݵ��ֽڴ��desc->count��.
	 */
	for (;;) {
		struct page *page;
		unsigned long ret_size, nr, ret;

		/* nr is the maximum number of bytes to copy from this page */
		/**
		 * ���index*4096+offset������������ڵ�����i_size�ֶ��е��ļ���С�����˳�ѭ��
		 * 
		 * ��Ӧ���Ƶ��û�̬��������ҳ�е��ֽ��������nr��,��Ӧ����4096.����offset!=0������������ݲ�ȫ���ļ���.
		 */
		nr = PAGE_CACHE_SIZE;
		/**
		 * �����������ڵ������ļ���С�ֶ�,���ѭ�����˳�.
		 */		
		if (index >= end_index) {
			/*
			 * �����ˣ�index��end_index֮��
			 */
			if (index > end_index)
				goto out;
		    /*
		     * index����end_index���������һ��
		     * nr���ļ����е��ֽ�������PAGE_SIZE����ȡ��, ȡ�����һҳ�е��ֽ���
			 */
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1; //
			/*
			 * offset�������һ��ҳ����ֽ�����Ҳ�ǳ������ļ��ķ�Χ
			 */
			if (nr <= offset) {
				goto out;
			}
		}
		/*
		 * offset��ʣ�µ��ֽ�����nr����Ϊƫ����֮��ʣ����Ҫ��ȡ���ֽ���
		 */
		nr = nr - offset;

		/**
		 * �����ǰ���̵�TIF_NEED_RESCHED,�����λ,�ͽ���һ�ε���.
		 */
		cond_resched();
		/**
		 * �����Ԥ����ҳ,�͵���page_cache_readahead������Щҳ��
		 */
		if (index == next_index && req_size) {
			ret_size = page_cache_readahead(mapping, &ra,
					filp, index, req_size); /*��*/
			next_index += ret_size;
			req_size -= ret_size;
		}

find_page:
		/**
		 * ����find_get_page����ҳ���ٻ������ҵ��������������ݵ�ҳ������.
		 */
		page = find_get_page(mapping, index); /*��*/
		/**
		 * page==NULL��ʾ�������ҳ���ڸ��ٻ�����
		 */
		if (unlikely(page == NULL)) {
			/**
			 * ����handle_ra_miss����Ԥ������.
			 */
			handle_ra_miss(mapping, &ra, index); /*��*/
			/*
			 * ��ת��no_cached_page��Ǵ�
			 */
			goto no_cached_page;
		}

		/**
		 * ���е���,˵��ҳ�Ѿ�λ��ҳ���ٻ�����,����־PG_uptodate.
		 * �����λ,��ʾҳ�������������µ�,�������Ӵ����ж�������.
		 * ���û����λ����ת��page_not_up_to_date
		 */
		if (!PageUptodate(page))
			goto page_not_up_to_date;
page_ok:

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		/**
		 * ���е���,��ʾҳ�Ѿ�λ�ڸ��ٻ�����,���������µ�.
		 * ����˵�Ѿ���ȷ�Ķ������ٻ�������.����Ӵ����ж�������.
		 */

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When (part of) the same page is read multiple times
		 * in succession, only mark it as accessed the first time.
		 */
		/**
		 * ����mark_page_accessed���PG_referenced��PG_active,�Ӷ���ʾ��ҳ�������ʲ��Ҳ�Ӧ�ñ�����.
		 * ���ͬһ�ļ���do_generic_file_read�ĺ���ִ����Ҫ������,��ô�������ֻ��Ҫ������һ��.
		 * ͨ��prev_index�������ж��Ƿ��ǵ�һ�ζ�ȡ
		 */
		if (prev_index != index)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		/*
		 * ���ڵ��˰�ҳ�е����ݿ������û�̬��������ʱ���ˣ�Ϊ����ô��������file_read_actor()����
		 */
		/**
		 * actor�Ǵ��ݽ����Ĳ���,��һ����file_read_actor����.
		 * �ú����������ǰ�ҳ�е����ݸ��Ƶ��û�̬��������.
		 */
		ret = actor(desc, page, offset, nr); /*��*/
		/**
		 * ���ݴ�����û�̬����������Ч�ֽ��������¾ֲ�����index��count��
		 * һ�������,��������һ���ֽ��Ѿ��������û�̬����������ôindex��1��offset��0
		 * ����index��ֵ����,offset��ֵ����ret�����ѿ������û�̬���������ֽ���
		 */
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;

		/**
		 * ����ҳ�����������ü�����.
		 */
		page_cache_release(page);
		/**
		 * desc->count != 0��ʾ��������Ҫ��,�Ǿͼ���ѭ������
		 */
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		/**
		 * ���е���,˵��ҳ��Ȼ�ڸ��ٻ�����,���������������.Ҳ����Ӵ����ж�ȡ.
		 */

		/**
		 * ����lock_page��ȡ��ҳ�Ļ������.���PG_locked�Ѿ���λ,��lock_page����������,ֱ����־����0.
		 */
		lock_page(page);

		/* Did it get unhashed before we got the lock? */
		/**
		 * ��Ȼ���ڻ���˶�ҳ������,������һ�����̿����ڽ������ǰ,�Ѿ���ҳ�Ӹ��ٻ�����ɾ����
		 * ������Ҫ���mapping�ֶ�,���ΪNULL,��ʾ�Ѿ�ɾ��,�ͽ������,�������ü���,�����¶���һҳ.
		 */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		/**
		 * �������е���,˵��ҳ�Ѿ�������,�����ڸ��ٻ�����.
		 * �ٴμ��PG_uptodate,����ñ�־��λ,����unlock_page������������(�Ǻ�,����������ò�����,���˴�����)
		 * ��ת��page_ok
		 */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/* Start the actual read. The read will unlock the page. */
		/**
		 * ����������IO�������Կ�ʼ��
		 * ����address_space�����readpage����
		 * ����ǿ�ʼ������IO����.���ἤ����̵�ҳ֮���IO���ݴ���.
		 */
		error = mapping->a_ops->readpage(filp, page); /*��*/

		if (unlikely(error))
			goto readpage_error;
		/**
		 * ���PG_uptodate��û�б���λ,�����lock_page,�ȴ�ҳ����Ч����.
		 * һ����ȡ������ɺ�ͱ���������˵�ǰ������IO���ݴ�������ǲ�ֹͣ������
		 * �����lock_page����ͬ���ź���������
		 */
		if (!PageUptodate(page)) {
			lock_page(page);
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_inode_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		/*
		 * i_size must be checked after we have done ->readpage.
		 *
		 * Checking i_size after the readpage allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		/**
		 * ҳ�����ļ���������ҳ��,�ͼ���ҳ������.����ת��out��Ǵ�
		 * ���������������������������ļ�ͬʱ��������������ɾ��.
		 */
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		/**
		 * ����Ӧ���Ƶ��û�̬���������ֽ���,����ھֲ�����nr��.һ��Ӧ����4096��
		 * ����offset��0(��ֻ�����ڶ����������βҳʱ)���������ݲ�ȫ���ļ���
		 */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1; //��������һҳ����ônr���һҳ�е��ֽ���
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset; /*�ļ���ʣ�µ��ֽ���*/
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		/**
		 * Ҫ����ҳ���ڻ�����
		 */
		if (!cached_page) {
			/**
			 * ����һ����ҳ
			 */
			cached_page = page_cache_alloc_cold(mapping); /*��*/
			if (!cached_page) {
				desc->error = -ENOMEM;
				goto out;
			}
		}
		/**
		 * ������ҳ�����������ٻ�����.��ҳ��PG_locked��־����λ.
		 * ����ҳ����LRU������.
		 */
		error = add_to_page_cache_lru(cached_page, mapping,
						index, GFP_KERNEL);
		if (error) {
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		page = cached_page;
		cached_page = NULL;
		/**
		 * ��ת��readpage��Ǵ�����ʼ���ļ�����.
		 */
		goto readpage;
	}

out:
	/**
	 * ��������Ļ���˵���Զ����������Ѿ�����,�͸���Ԥ�����ݽṹfilp->f_ra����������Ѿ���˳����ļ�����(�μ��ļ�Ԥ��).
	 */	
	*_ra = ra;

	/**
	 * ��index*4096+offsetֵ����*ppos,�Ӷ������Ժ����read()��write()����˳����ʵ�λ��
	 * ����ppos,�Ժ�read����write�ͻ�����λ�ÿ�ʼ.
	 */
	*ppos = ((loff_t) index << PAGE_CACHE_SHIFT) + offset;
	if (cached_page)
		page_cache_release(cached_page);
	/**
	 * ����update_atime�ѵ�ǰʱ�������ļ������ڵ��i_atime�ֶ���,���������Ϊ��󷵻�
	 */
	if (filp)
		file_accessed(filp);
}

EXPORT_SYMBOL(do_generic_mapping_read);

/**
 * ��ҳ�е����ݸ��Ƶ��û�̬������.
 */
int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page, KM_USER0);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr, KM_USER0);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	/**
	 * kmapΪ���ڸ߶��ڴ��е�ҳ�������õ��ں�ӳ��.
	 */
	kaddr = kmap(page);
	/**
	 * ����ҳ�е����ݵ��û�̬�ռ�.
	 */
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	/**
	 * ����kunmap�ͷ�ҳ�������ں�ӳ��
	 */
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	/**
	 * ����read_descriptor_t���ֶ�.
	 */
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/*
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
/**
 * �����ļ�ϵͳʵ��ͬ�����첽������ʹ�õ�ͨ�����̡�
 * ���������: ����ҳ���ٻ����ļ���ϵͳ����read()��������ͬ������
 * iocb:		���Ʋ���,kiocb��������ַ
 * iov:			iovec�����������ַ��iovec���������鱻����generic_file_read����ʱֻ��һ��Ԫ�أ���Ԫ���������������ݵ��û�̬��������
 * nr_segs:		iovec���������鳤�ȡ�
 * ppos:		�ļ���ǰָ�������
 */
ssize_t
__generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t *ppos)
{
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg;
	size_t count;

	count = 0;
	/**
	 * ����access_ok�����iovec���������������û�̬�������Ƿ���Ч�������Ч����-EFAULT
	 */
	for (seg = 0; seg < nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		count += iv->iov_len;
		if (unlikely((ssize_t)(count|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(VERIFY_WRITE, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		nr_segs = seg;
		count -= iv->iov_len;	/* This segment is no good */
		break;
	}

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	/*
	 * ����ֱ��IO ,��Ч�����´���
	 *
         if (filp->f_flags & O_DIRECT) {
             if (count == 0 || *ppos > filp->f_mapping->host->i_size)
                 return 0;
             retval = generic_file_direct_IO(READ, iocb, iov, *ppos, 1);
             if (retval > 0)
                 *ppos += retval;
             file_accessed(filp);
             return retval;
         }
     
	 *
     */
	if (filp->f_flags & O_DIRECT) {
		loff_t pos = *ppos, size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		retval = 0;
		if (!count)
			goto out; /* skip atime */
		size = i_size_read(inode);
		if (pos < size) {
			/* ��������д����̺��ٽ���ֱ��IO */
			retval = generic_file_direct_IO(READ, iocb,
						iov, pos, nr_segs); /*��*/
			if (retval >= 0 && !is_sync_kiocb(iocb))
				retval = -EIOCBQUEUED;
			if (retval > 0)
				*ppos = pos + retval;
		}
		file_accessed(filp); /*��*/
		goto out;
	}

	retval = 0;
	if (count) {
		/* ��������ÿһ���� */
		for (seg = 0; seg < nr_segs; seg++) {
			/**
			 * Ϊÿ��������������һ����������������
			 * �ýṹ����뵥���û�̬��������ص��ļ��������ĵ�ǰ״̬��
			 */
			read_descriptor_t desc;

			desc.written = 0;
			desc.arg.buf = iov[seg].iov_base;
			desc.count = iov[seg].iov_len;
			if (desc.count == 0)
				continue;
			desc.error = 0;
			/**
			 * ����do_generic_file_read���Ӵ��̶����������ҳ�������ǿ������û�̬��������
			 */
			do_generic_file_read(filp,ppos,&desc,file_read_actor);
			/*
			 * ���ؿ������û�̬���������ֽ�������read_descriptor_t��writtenֵ
			 */
			retval += desc.written;
			if (!retval) {
				retval = desc.error;
				break;
			}
		}
	}
out:
	return retval;
}

EXPORT_SYMBOL(__generic_file_aio_read);

ssize_t
generic_file_aio_read(struct kiocb *iocb, char __user *buf, size_t count, loff_t pos)
{
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };

	BUG_ON(iocb->ki_pos != pos);
	return __generic_file_aio_read(iocb, &local_iov, 1, &iocb->ki_pos);
}

EXPORT_SYMBOL(generic_file_aio_read);

/**
 * ��ȡ�󲿷ִ����ļ�ϵͳ�е���ͨ�ļ����κο��豸�ļ���
 * ʵ���˼������д����ļ�ϵͳ�е���ͨ�ļ����κο��ļ���read����
 * filp:	�ļ�����ĵ�ַ��
 * buf:		�û�̬�����������Ե�ַ��
 * count:	Ҫ��ȡ���ַ�������
 * ppos:	ָ��һ��������ָ�룬�ñ�����Ŷ�������ʼ�����ļ�ƫ������ͨ����filp��f_pos�ֶΡ�
 */
ssize_t
generic_file_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	/**
	 * ��ʼ������������
	 * (1) ��ʼ��iovec���������������û�̬�������ĵ�ַ�볤�ȡ�
	 */
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	ssize_t ret;

	/**
	 * (2) ����init_sync_kiocb��ʼ��kiocb�������������������������е�ͬ�����첽IO���������״̬��
	 */
	init_sync_kiocb(&kiocb, filp);
	/**
	 * ����__generic_file_aio_read,����kiocb��iovec���ݸ���
	 * __generic_file_aio_read�����������������ļ��ж�ȡ���ݡ�
	 * �����������Ч�ַ������ء�
	 */
	ret = __generic_file_aio_read(&kiocb, &local_iov, 1, ppos); /*��*/
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	/*���ض�ȡ���ֽ���*/
	return ret;
}

EXPORT_SYMBOL(generic_file_read);

int file_send_actor(read_descriptor_t * desc, struct page *page, unsigned long offset, unsigned long size)
{
	ssize_t written;
	unsigned long count = desc->count;
	struct file *file = desc->arg.data;

	if (size > count)
		size = count;

	written = file->f_op->sendpage(file, page, offset,
				       size, &file->f_pos, size<count);
	if (written < 0) {
		desc->error = written;
		written = 0;
	}
	desc->count = count - written;
	desc->written += written;
	return written;
}

ssize_t generic_file_sendfile(struct file *in_file, loff_t *ppos,
			 size_t count, read_actor_t actor, void *target)
{
	read_descriptor_t desc;

	if (!count)
		return 0;

	desc.written = 0;
	desc.count = count;
	desc.arg.data = target;
	desc.error = 0;

	do_generic_file_read(in_file, ppos, &desc, actor);
	if (desc.written)
		return desc.written;
	return desc.error;
}

EXPORT_SYMBOL(generic_file_sendfile);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     unsigned long index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops || !mapping->a_ops->readpage)
		return -EINVAL;

	force_page_cache_readahead(mapping, filp, index,
					max_sane_readahead(nr));
	return 0;
}

asmlinkage ssize_t sys_readahead(int fd, loff_t offset, size_t count)
{
	ssize_t ret;
	struct file *file;

	ret = -EBADF;
	file = fget(fd);
	if (file) {
		if (file->f_mode & FMODE_READ) {
			struct address_space *mapping = file->f_mapping;
			unsigned long start = offset >> PAGE_CACHE_SHIFT;
			unsigned long end = (offset + count - 1) >> PAGE_CACHE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, file, start, len);
		}
		fput(file);
	}
	return ret;
}

#ifdef CONFIG_MMU
/*
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 */
static int FASTCALL(page_cache_read(struct file * file, unsigned long offset));
static int fastcall page_cache_read(struct file * file, unsigned long offset)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page; 
	int error;

	page = page_cache_alloc_cold(mapping);
	if (!page)
		return -ENOMEM;

	error = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
	if (!error) {
		error = mapping->a_ops->readpage(file, page);
		page_cache_release(page);
		return error;
	}

	/*
	 * We arrive here in the unlikely event that someone 
	 * raced with us and added our page to the cache first
	 * or we are out of memory for radix-tree nodes.
	 */
	page_cache_release(page);
	return error == -EEXIST ? 0 : error; /*ע��: ����ֵ0��ʾʧ�ܣ������ʾ�ɹ�*/
}

#define MMAP_LOTSAMISS  (100)

/*
 * filemap_nopage() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 */
/**
 * ���������ļ�ϵͳ�Ϳ��豸�ļ���ͨ��������ʵ���ڴ�ӳ���nopage������
 * ����������ҳ���ٻ����в����������ҳ�����û���ҵ���Ӧ��ҳ����������ͱ��뽫��Ӵ����϶��롣
 * 		area:		������ҳ��������������������ַ��
 * 		address:	������ҳ�����Ե�ַ��
 * 		type:		��ź�����⵽��ȱҳ����(VM_FAULT_MAJOR����VM_FAULT_MINOR)�ı�����ָ�롣
 */
struct page * filemap_nopage(struct vm_area_struct * area, unsigned long address, int *type)
{
	int error;
	/**
	 * ��area�õ��ļ������ַ��address_space�����ַ�������ڵ�����ַ��
	 */
	struct file *file = area->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long size, pgoff, endoff;
	int did_readaround = 0, majmin = VM_FAULT_MINOR;

	/**
	 * ����vm_start��vm_pgoff��ȷ����address��ʼ��ҳ��Ӧ���������ļ��е�ƫ������
	 */
	pgoff = ((address - area->vm_start) >> PAGE_CACHE_SHIFT) + area->vm_pgoff;
	endoff = ((area->vm_end - area->vm_start) >> PAGE_CACHE_SHIFT) + area->vm_pgoff;

retry_all:
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	/**
	 * ����ļ�ƫ���������ļ���С������ǣ��ͷ���NULL�����ʾ������ҳʧ�ܡ�
	 * ����ȱҳ���ɵ��Գ���ͨ��ptraceϵͳ���ø�����һ����������ġ���Ҳ��outside_data_content������current->mm == area->mm��ԭ��
	 */
	if (pgoff >= size)
		goto outside_data_content;

	/* If we don't want any read-ahead, don't bother */
	/**
	 * �����������VM_RAND_READ��־�����á���ٶ������������ʽ���ڴ�ӳ���е�ҳ�������Ԥ����
	 */
	if (VM_RandomReadHint(area))
		goto no_cached_page;

	/*
	 * The "size" of the file, as far as mmap is concerned, isn't bigger
	 * than the mapping
	 */
	if (size > endoff)
		size = endoff;

	/*
	 * The readahead code wants to be told about each and every page
	 * so it can build and shrink its windows appropriately
	 *
	 * For sequential accesses, we use the generic readahead logic.
	 */
	/**
	 * �ļ�������VM_SEQ_READ����ô��Ҫ����Ԥ����
	 */
	if (VM_SequentialReadHint(area))
		page_cache_readahead(mapping, ra, file, pgoff, 1);

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	/**
	 * ����find_get_page��ҳ���ٻ�����Ѱ����address_space������ļ�ƫ������ʶ��ҳ��
	 */
	page = find_get_page(mapping, pgoff);
	/**
	 * ��ҳ���ٻ�����û���ҵ���Ӧ��ҳ��
	 */
	if (!page) {
		unsigned long ra_pages;

		/**
		 * ������е��ˣ�˵��û����ҳ���ٻ������ҵ�ҳ������VM_SEQ_READ��־��
		 */
		if (VM_SequentialReadHint(area)) {
			/**
			 * ����ñ�־��λ������ҳû���ڻ����У�˵��Ԥ���㷨ʧ�ܣ��ں˻�ǿ��Ԥ���������е�ҳ��
			 * ����handle_ra_miss������Ԥ��������
			 */
			handle_ra_miss(mapping, ra, pgoff);
			goto no_cached_page;
		}

		/**
		 * û������VM_SEQ_READ��־�����ļ�file_ra_state�������е�mmap_miss��������1.
		 */
		ra->mmap_miss++;

		/*
		 * Do we miss much more than hit in this file? If so,
		 * stop bothering with read-ahead. It will only hurt.
		 */
		/**
		 * ���ʧ����Զ�����������������Ԥ����
		 */
		if (ra->mmap_miss > ra->mmap_hit + MMAP_LOTSAMISS)
			goto no_cached_page;

		/*
		 * To keep the pgmajfault counter straight, we need to
		 * check did_readaround, as this is an inner loop.
		 */
		if (!did_readaround) {
			majmin = VM_FAULT_MAJOR;
			inc_page_state(pgmajfault);
		}
		did_readaround = 1;
		ra_pages = max_sane_readahead(file->f_ra.ra_pages);
		/**
		 * ���ra_pages����0����ʾԤ��û�����ý�ֹ
		 */
		if (ra_pages) {
			pgoff_t start = 0;

			if (pgoff > ra_pages / 2)
				start = pgoff - ra_pages / 2;
			/**
			 * ����do_page_cache_readahead����Χ������ҳǰ���һ��ҳ��
			 */
			do_page_cache_readahead(mapping, file, start, ra_pages);
		}
		/**
		 * �ٴε���find_get_page��ҳ���ٻ����в���ҳ��
		 */
		page = find_get_page(mapping, pgoff);
		if (!page)
			goto no_cached_page;
	}

	/**
	 * ����ҳ�Ѿ���ҳ���ٻ����У���mmap_hit��������1.
	 */
	if (!did_readaround)
		ra->mmap_hit++;

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	/**
	 * ҳ�������µġ�
	 */
	if (!PageUptodate(page))
		goto page_not_uptodate;

success:
	/*
	 * Found the page and have a reference on it.
	 */
	/**
	 * �������ҳ�ķ��ʱ�־��
	 */
	mark_page_accessed(page);
	/**
	 * type��ʾ����ҳ���ٻ����У����ǴӴ������ҵ�ҳ������°档
	 * �����ҳ���ٻ������ҵ���ҳ�����°棬��*type����ΪVM_FAULT_MINOR����������ΪVM_FAULT_MAJOR
	 */
	if (type)
		*type = majmin;
	/**
	 * ��������ҳ��ַ��
	 */
	return page;

outside_data_content:
	/*
	 * An external ptracer can access pages that normally aren't
	 * accessible..
	 */
	if (area->vm_mm == current->mm)
		return NULL;
	/* Fall through to the non-read-ahead case */
no_cached_page:
	/*
	 * We're only likely to ever get here if MADV_RANDOM is in
	 * effect.
	 */
	/**
	 * ��ҳ���ٻ�����û���ҵ�ҳ�������page_cache_read��
	 * �ú����������ҳ�Ƿ���ҳ���ٻ����У�������ڣ������һ����ҳ�򣬰���׷�ӵ�ҳ�������档
	 * ִ��mapping->a_ops->readpage����������һ��IO�����Ӵ��̶����ҳ���ݡ�
	 *
	 * ����ֻ����һҳ����ӳ��ĵ�ǰҳ��û�н���Ԥ��
	 */
	error = page_cache_read(file, pgoff); /*��*/
	/**
	 * grab_swap_token������Ϊ��ǰ���̷���һ��������ǡ�
	 */
	grab_swap_token(); /*��*/

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find; /*��*/

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	if (error == -ENOMEM)
		return NOPAGE_OOM;
	return NULL;

/**
 * ҳ�������µġ�
 */
page_not_uptodate:
	if (!did_readaround) {
		majmin = VM_FAULT_MAJOR;
		inc_page_state(pgmajfault);
	}
	/**
	 * ��������ҳ��������IO���ݴ��䣬Ȼ��ȴ�������ɡ�
	 */
	lock_page(page);

	/* Did it get unhashed while we waited for it? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry_all;
	}

	/* Did somebody else get it up-to-date? */
	/**
	 * �������������ռ�˱����̣�����ҳ������ˣ��Ͳ����ٴν���IO�����ˡ�
	 */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	/**
	 * ����readpage�ص���������IO���ݴ��䡣
	 */
	if (!mapping->a_ops->readpage(file, page)) { /*��*/
		/**
		 * �ȴ�ҳ�洫����ϡ�
		 */
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success; /*��*/
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry_all;
	}

	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}
	ClearPageError(page);
	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
	page_cache_release(page);
	return NULL;
}

EXPORT_SYMBOL(filemap_nopage);

static struct page * filemap_getpage(struct file *file, unsigned long pgoff,
					int nonblock)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	int error;

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	page = find_get_page(mapping, pgoff);
	if (!page) {
		if (nonblock)
			return NULL;
		goto no_cached_page;
	}

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	if (!PageUptodate(page))
		goto page_not_uptodate;

success:
	/*
	 * Found the page and have a reference on it.
	 */
	mark_page_accessed(page);
	return page;

no_cached_page:
	error = page_cache_read(file, pgoff);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	return NULL;

page_not_uptodate:
	lock_page(page);

	/* Did it get unhashed while we waited for it? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}

	/* Did somebody else get it up-to-date? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}
	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	ClearPageError(page);
	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
err:
	page_cache_release(page);

	return NULL;
}

/** 
 * ��ͨ�ļ���populate����
 */
int filemap_populate(struct vm_area_struct *vma, unsigned long addr,
		unsigned long len, pgprot_t prot, unsigned long pgoff,
		int nonblock)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned long size;
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	int err;

	/**
	 * ���MAP_NONBLOCK��־�������0���͵���force_page_cache_readaheadԤ����ӳ���ļ���ҳ��
	 */
	if (!nonblock)
		force_page_cache_readahead(mapping, vma->vm_file,
					pgoff, len >> PAGE_CACHE_SHIFT);

/**
 * ѭ�������ӳ���ÿһҳ��
 */
repeat:
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (pgoff + (len >> PAGE_CACHE_SHIFT) > size)
		return -EINVAL;

	/**
	 * �ڸ��ٻ����в���ҳ��
	 */
	page = filemap_getpage(file, pgoff, nonblock);
	/**
	 * �����в����ڣ������MAP_NONBLOCK���˳���(�ȴ�NONBLOCK�����̽�ҳ��Ӵ��̶���)
	 */
	if (!page && !nonblock)
		return -ENOMEM;
	if (page) {/* ��������д���ҳ����ҳ���õ�pte */
		err = install_page(mm, vma, addr, page, prot);
		if (err) {
			page_cache_release(page);
			return err;
		}
	} else {/* ҳ���ڻ����� */
		/**
		 * ���û����ҳ���ٻ������ҵ���ҳ�������������ļ�ҳ��ƫ��������ڸ����Ե�ַ��Ӧ��ҳ����ĸ�32λ������ҳ�����Presentλ��0��Dirtyλ��λ
		 *
		 * ��ҳ���н���һ��pte,��presentλ��0��dirtyλ��λ��������ȱҳ�쳣�����ҳ��
		 * handle_pte_fault����do_file_page�����õ�ҳ��������������������populate��������ҳ��
		 */
		err = install_file_pte(mm, vma, addr, pgoff, prot);
		if (err)
			return err;
	}

	len -= PAGE_SIZE;
	addr += PAGE_SIZE;
	pgoff++;
	if (len)
		goto repeat;

	return 0;
}

struct vm_operations_struct generic_file_vm_ops = {
	.nopage		= filemap_nopage,
	.populate	= filemap_populate,
};

/* This is used for a general mmap of a disk file */
/**
 * ������ļ�ϵͳ�ڴ�ӳ���mmapʵ�ַ�����
 */
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	/**
	 * ����ǰʱ�丳��i_atime�ֶΣ����������ڵ���Ϊ��
	 */
	file_accessed(file);
	/**
	 * �����߳�����ӳ�䷽����
	 */
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}
EXPORT_SYMBOL(filemap_populate);

/*
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static inline struct page *__read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	/**
	 * find_get_page���ҳ�Ƿ��Ѿ���ҳ���ٻ����С�
	 */
	page = find_get_page(mapping, index); /*��*/
	if (!page) {/* ҳ���ڸ��ٻ����� */
		if (!cached_page) {
			/**
			 * ����һ����ҳ��
			 */
			cached_page = page_cache_alloc_cold(mapping); /*��*/
			if (!cached_page)
				return ERR_PTR(-ENOMEM);
		}
		/**
		 * ��ҳ���ٻ����в�����Ӧ��ҳ��������
		 * ����ҳ����������ķǻLRU�����С�
		 */
		err = add_to_page_cache_lru(cached_page, mapping,
					index, GFP_KERNEL); /*��*/
		if (err == -EEXIST)
			goto repeat;
		if (err < 0) {
			/* Presumably ENOMEM for radix tree node */
			page_cache_release(cached_page);
			return ERR_PTR(err);
		}
		page = cached_page;
		cached_page = NULL;
		err = filler(data, page); /*��*/ /*�Ӵ��̶�ȡҳ������*/
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		}
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

/*
 * Read into the page cache. If a page already exists,
 * and PageUptodate() is not set, try to fill the page.
 */
/**
 * ȷ�����ٻ����а������°汾��ָ��ҳ��
 * mapping:   ҳ������address_space
 * index:	  ������ҳ��ƫ������ֵ
 * filter:    �Ӵ��̶�ȡҳ���ݵĻص�����
 * data:      ���ݸ�filter������ָ�룬ͨ��ΪNULL
 */
struct page *read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page;
	int err;

retry:
	/*
	 * ȷ��ҳ����ҳ�����У�û����ҳ�����еĽ����µ�ҳ��
	 */
	page = __read_cache_page(mapping, index, filler, data); /*��*/
	if (IS_ERR(page))
		goto out;
	/**
	 * ҳ�Ѿ���ҳ���ٻ������ˣ�mark_page_accessed��¼ҳ�Ѿ������ʹ�����ʵ��
	 */
	mark_page_accessed(page);
	/**
	 * �鿴ҳ�Ƿ�Ϊ���¡�PG_uptodateΪ0��ʾҳ�������µġ�
	 */
	if (PageUptodate(page)) /*��*/
		goto out;

	/**
	 * ҳ�������µģ�����filter�Ӵ��̶�ȡҳ��������PG_uptodate��־��(filter����������update)
	 */
	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page); /*��*/
	if (err < 0) {
		page_cache_release(page);
		page = ERR_PTR(err);
	}
 out:
 	/*
 	 * ����ҳ����������ַ
 	 */
	return page;
}

EXPORT_SYMBOL(read_cache_page);

/*
 * If the page was newly created, increment its refcount and add it to the
 * caller's lru-buffering pagevec.  This function is specifically for
 * generic_file_write().
 */
static inline struct page *
__grab_cache_page(struct address_space *mapping, unsigned long index,
			struct page **cached_page, struct pagevec *lru_pvec)
{
	int err;
	struct page *page;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!*cached_page) {
			*cached_page = page_cache_alloc(mapping);
			if (!*cached_page)
				return NULL;
		}
		err = add_to_page_cache(*cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err == 0) {
			page = *cached_page;
			page_cache_get(page);
			if (!pagevec_add(lru_pvec, page))
				__pagevec_lru_add(lru_pvec);
			*cached_page = NULL;
		}
	}
	return page;
}

/*
 * The logic we want is
 *
 *	if suid or (sgid and xgrp)
 *		remove privs
 */
int remove_suid(struct dentry *dentry)
{
	mode_t mode = dentry->d_inode->i_mode;
	int kill = 0;
	int result = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && !capable(CAP_FSETID))) {
		struct iattr newattrs;

		newattrs.ia_valid = ATTR_FORCE | kill;
		result = notify_change(dentry, &newattrs);
	}
	return result;
}
EXPORT_SYMBOL(remove_suid);

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then clear the page
 * out to (offset+bytes) and return the number of bytes which were copied.
 */
static inline size_t
filemap_copy_from_user(struct page *page, unsigned long offset,
			const char __user *buf, unsigned bytes)
{
	char *kaddr;
	int left;

	kaddr = kmap_atomic(page, KM_USER0);
	left = __copy_from_user_inatomic(kaddr + offset, buf, bytes);
	kunmap_atomic(kaddr, KM_USER0);

	if (left != 0) {
		/* Do it the slow way */
		kaddr = kmap(page);
		left = __copy_from_user(kaddr + offset, buf, bytes);
		kunmap(page);
	}
	return bytes - left;
}

static size_t
__filemap_copy_from_user_iovec(char *vaddr, 
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left)) {
			/* zero the rest of the target like __copy_from_user */
			if (bytes)
				memset(vaddr, 0, bytes);
			break;
		}
	}
	return copied - left;
}

/*
 * This has the same sideeffects and return value as filemap_copy_from_user().
 * The difference is that on a fault we need to memset the remainder of the
 * page (out to offset+bytes), to emulate filemap_copy_from_user()'s
 * single-segment behaviour.
 */
static inline size_t
filemap_copy_from_user_iovec(struct page *page, unsigned long offset,
			const struct iovec *iov, size_t base, size_t bytes)
{
	char *kaddr;
	size_t copied;

	kaddr = kmap_atomic(page, KM_USER0);
	copied = __filemap_copy_from_user_iovec(kaddr + offset, iov,
						base, bytes);
	kunmap_atomic(kaddr, KM_USER0);
	if (copied != bytes) {
		kaddr = kmap(page);
		copied = __filemap_copy_from_user_iovec(kaddr + offset, iov,
							base, bytes);
		kunmap(page);
	}
	return copied;
}

static inline void
filemap_set_next_iovec(const struct iovec **iovp, size_t *basep, size_t bytes)
{
	const struct iovec *iov = *iovp;
	size_t base = *basep;

	while (bytes) {
		int copy = min(bytes, iov->iov_len - base);

		bytes -= copy;
		base += copy;
		if (iov->iov_len == base) {
			iov++;
			base = 0;
		}
	}
	*iovp = iov;
	*basep = base;
}

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position aor amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
inline int generic_write_checks(struct file *file, loff_t *pos, size_t *count, int isblk)
{
	struct inode *inode = file->f_mapping->host;
	unsigned long limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;

        if (unlikely(*pos < 0))
                return -EINVAL;

        if (unlikely(file->f_error)) {
                int err = file->f_error;
                file->f_error = 0;
                return err;
        }

	if (!isblk) {
		/* FIXME: this is for backwards compatibility with 2.4 */
		/**
		 * ������ǿ��豸(����ͨ�ļ�)
		 * ����ָ����O_APPEND���ͽ�ppos��Ϊ�ļ�β���Ӷ���������׷�ӵ��ļ��ĺ��档
		 */
		if (file->f_flags & O_APPEND)
                        *pos = i_size_read(inode);

		/**
		 * ���ļ���С���м�顣
		 * �˴��Ǽ��������ֵ���ܳ���ulimit�����ơ�
		 */
		if (limit != RLIM_INFINITY) {
			if (*pos >= limit) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			if (*count > limit - (typeof(limit))*pos) {
				*count = limit - (typeof(limit))*pos;
			}
		}
	}

	/*
	 * LFS rule
	 */
	/**
	 * ����ļ�û��O_LARGEFILE��־����ô�Ͳ��ܳ���2G��
	 */
	if (unlikely(*pos + *count > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (*pos >= MAX_NON_LFS) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		if (*count > MAX_NON_LFS - (unsigned long)*pos) {
			*count = MAX_NON_LFS - (unsigned long)*pos;
		}
	}

	/*
	 * Are we about to exceed the fs block limit ?
	 *
	 * If we have written data it becomes a short write.  If we have
	 * exceeded without writing data we send a signal and return EFBIG.
	 * Linus frestrict idea will clean these up nicely..
	 */
	/**
	 * ���ܰ�һ����ͨ�ļ����󵽳����ļ�ϵͳ�����ޡ�
	 */
	if (likely(!isblk)) {
		if (unlikely(*pos >= inode->i_sb->s_maxbytes)) {
			if (*count || *pos > inode->i_sb->s_maxbytes) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			/* zero-length writes at ->s_maxbytes are OK */
		}

		if (unlikely(*pos + *count > inode->i_sb->s_maxbytes))
			*count = inode->i_sb->s_maxbytes - *pos;
	} else {
		loff_t isize;
		if (bdev_read_only(I_BDEV(inode)))
			return -EPERM;
		isize = i_size_read(inode);
		if (*pos >= isize) {
			if (*count || *pos > isize)
				return -ENOSPC;
		}

		if (*pos + *count > isize)
			*count = isize - *pos;
	}
	return 0;
}
EXPORT_SYMBOL(generic_write_checks);

ssize_t
generic_file_direct_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long *nr_segs, loff_t pos, loff_t *ppos,
		size_t count, size_t ocount)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t		written;

	if (count != ocount)
		*nr_segs = iov_shorten((struct iovec *)iov, *nr_segs, count);

	written = generic_file_direct_IO(WRITE, iocb, iov, pos, *nr_segs); /*��*/
	if (written > 0) {
		loff_t end = pos + written;
		if (end > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode,  end);
			mark_inode_dirty(inode);
		}
		*ppos = end;
	}

	/*
	 * Sync the fs metadata but not the minor inode changes and
	 * of course not the data as we did direct DMA for the IO.
	 * i_sem is held, which protects generic_osync_inode() from
	 * livelocking.
	 */
	if (written >= 0 && file->f_flags & O_SYNC)
		generic_osync_inode(inode, mapping, OSYNC_METADATA);
	if (written == count && !is_sync_kiocb(iocb))
		written = -EIOCBQUEUED;
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);

ssize_t
generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos, loff_t *ppos,
		size_t count, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct address_space_operations *a_ops = mapping->a_ops;
	struct inode 	*inode = mapping->host;
	long		status = 0;
	struct page	*page;
	struct page	*cached_page = NULL;
	size_t		bytes;
	struct pagevec	lru_pvec;
	const struct iovec *cur_iov = iov; /* current iovec */
	size_t		iov_base = 0;	   /* offset in the current iovec */
	char __user	*buf;

	pagevec_init(&lru_pvec, 0);

	/*
	 * handle partial DIO write.  Adjust cur_iov if needed.
	 */
	if (likely(nr_segs == 1))
		buf = iov->iov_base + written;
	else {
		filemap_set_next_iovec(&cur_iov, &iov_base, written);
		buf = iov->iov_base + iov_base;
	}

	/**
	 * ѭ������ÿһҳ��
	 */
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;

		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 */
		fault_in_pages_readable(buf, bytes);

		/**
		 * __grab_cache_page�����find_lock_page��ҳ���ٻ�����������ҳ�����������ü�������������
		 * �����ҳ����ҳ���ٻ����У������һ����ҳ������add_to_page_cache��ҳ���ٻ����в����ҳ��ͬʱ���ڴ�������ķǻ�����в���һҳ��
		 */
		page = __grab_cache_page(mapping,index,&cached_page,&lru_pvec); /*��*/
		if (!page) {
			status = -ENOMEM;
			break;
		}

		/**
		 * ���������ڵ��prepare_write����Ӧ�ĺ�����Ϊ��ҳ����ͳ�ʼ���������ײ���
		 * ��ͨ�ļ�     ext2_prepare_write
		 * ���豸�ļ�   blkdev_prepare_write
		 */
		status = a_ops->prepare_write(file, page, offset, offset+bytes); /*��*/
		if (unlikely(status)) {
			loff_t isize = i_size_read(inode);
			/*
			 * prepare_write() may have instantiated a few blocks
			 * outside i_size.  Trim these off again.
			 */
			unlock_page(page);
			page_cache_release(page);
			if (pos + bytes > isize)
				vmtruncate(inode, isize);
			break;
		}
		/**
		 * ͨ��kmap������ʱӳ�䣬Ȼ�����copy_from_user���û�̬�������е��ַ�������ҳ�С�Ȼ���ͷ���ʱӳ�䡣
		 */
		if (likely(nr_segs == 1))
			copied = filemap_copy_from_user(page, offset,
							buf, bytes); /*��*/
		else
			copied = filemap_copy_from_user_iovec(page, offset,
						cur_iov, iov_base, bytes);
		flush_dcache_page(page);
		/**
		 * commit_write���������������Ϊ�࣬�Ա��������д�ش��̡�
		 * ��ͨ�ļ�     generic_commit_write
		 * ���豸�ļ�   blkdev_commit_write
		 */
		status = a_ops->commit_write(file, page, offset, offset+bytes);
		if (likely(copied > 0)) {
			if (!status)
				status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
				if (unlikely(nr_segs > 1))
					filemap_set_next_iovec(&cur_iov,
							&iov_base, status);
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		/**
		 * ���ҳ���PG_locked��־�������ѵȴ���ҳ���κν��̡�
		 */
		unlock_page(page);
		/**
		 * ����ҳ����ʱ�־����Ϊ�ڴ�����㷨��ʹ�á�
		 */
		mark_page_accessed(page);
		/**
		 * ����ҳ���ü�����
		 */
		page_cache_release(page);
		if (status < 0)
			break;
		/**
		 * ���ҳ������������ҳ�����Ƿ񳬹�һ���̶��ķ�ֵ(һ��Ϊϵͳ��ҳ��40%)����������������writeback_inodes��ˢ�¼�ʮҳ�����̡�
		 */
		balance_dirty_pages_ratelimited(mapping);

		/**
		 * ����һ����ռ�㡣
		 */
		cond_resched();
	} while (count);

    /*
     * ���ڣ���д���������漰���ļ�������ҳ���Ѵ�������*ppos��ֵ����������ָ������һ����д����ַ�֮���λ��
     */
	*ppos = pos;

	if (cached_page)
		page_cache_release(cached_page);

	/*
	 * For now, when the user asks for O_SYNC, we'll actually give O_DSYNC
	 */
	if (likely(status >= 0)) {
		if (unlikely((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
			if (!a_ops->writepage || !is_sync_kiocb(iocb))
				status = generic_osync_inode(inode, mapping,
						OSYNC_METADATA|OSYNC_DATA);
		}
  	}
	
	/*
	 * If we get here for O_DIRECT writes then we must have fallen through
	 * to buffered writes (block instantiation inside i_size).  So we sync
	 * the file data here, to try to honour O_DIRECT expectations.
	 */
	if (unlikely(file->f_flags & O_DIRECT) && written)
		status = filemap_write_and_wait(mapping);

	pagevec_lru_add(&lru_pvec);
	return written ? written : status;
}
EXPORT_SYMBOL(generic_file_buffered_write);

ssize_t
__generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	size_t ocount;		/* original count */
	size_t count;		/* after file limit checks */
	/**
	 * ȷ����д�ļ������ڵ�����inode��
	 * ����ļ���һ�����豸�ļ��������һ��bdev�����ļ�ϵͳ�������ڵ㡣
	 */
	struct inode 	*inode = mapping->host;
	unsigned long	seg;
	loff_t		pos;
	ssize_t		written;
	ssize_t		err;

	ocount = 0;
	for (seg = 0; seg < nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		ocount += iv->iov_len;
		if (unlikely((ssize_t)(ocount|iv->iov_len) < 0))
			return -EINVAL;
		/**
		 * ����access_okȷ��iovec���������������û�̬����������Ч�ġ�
		 */
		if (access_ok(VERIFY_READ, iv->iov_base, iv->iov_len)) /*��*/
			continue;
		if (seg == 0)
			return -EFAULT;
		nr_segs = seg;
		ocount -= iv->iov_len;	/* This segment is no good */
		break;
	}

	count = ocount;
	pos = *ppos;

	vfs_check_frozen(inode->i_sb, SB_FREEZE_WRITE);

	/* We can write back this queue in page reclaim */
	/**
	 * ���ļ���backing_dev_info����Ϊcurrent->backing_dev_info
	 * ��������ʹ��Ӧ���������ӵ���ģ��������Ҳ������ǰ����д����file->f_mappingӵ�е���ҳ��
	 */
	current->backing_dev_info = mapping->backing_dev_info;
	written = 0;

	/**
	 * һЩ�����顣
	 */
	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode)); /*��*/
	if (err)
		goto out;

	if (count == 0)
		goto out;

	/**
	 * �������趨�ļ�Ȩ�ޡ�
	 */
	err = remove_suid(file->f_dentry); /*��*/
	if (err)
		goto out;

	/**
	 * ����ǰʱ������inode->mtime�ֶ��У�Ҳ�����inode->ctime�С�
	 * ���߷ֱ��ʾ�ļ�д����������ʱ�䣬�Լ��޸�������������ʱ���С�
	 * ���ҽ������ڵ������Ϊ��
	 */
	inode_update_time(inode, 1); /*��*/

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (unlikely(file->f_flags & O_DIRECT)) {
		written = generic_file_direct_write(iocb, iov,
				&nr_segs, pos, ppos, count, ocount); /*��*/
		if (written < 0 || written == count)
			goto out;
		/*
		 * direct-io write to a hole: fall through to buffered I/O
		 * for completing the rest of the request.
		 */
		pos += written;
		count -= written;
	}

	/**
	 * ѭ�������Ը���д�����е������ļ�ҳ��
	 */
	written = generic_file_buffered_write(iocb, iov, nr_segs,
			pos, ppos, count, written);/*��*/
out:
	/**
	 * �ָ�current->backing_dev_info
	 */
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(generic_file_aio_write_nolock);

ssize_t
generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	loff_t pos = *ppos;

	ret = __generic_file_aio_write_nolock(iocb, iov, nr_segs, ppos); /*��*/

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range_nolock(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

ssize_t
__generic_file_write_nolock(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	/**
	 * ��ʼ��kiocb���͵ľֲ�������
	 */
	init_sync_kiocb(&kiocb, file);
	/**
	 * �ú�������ҳ���Ϊ�ࡣ
	 */
	ret = __generic_file_aio_write_nolock(&kiocb, iov, nr_segs, ppos);
	if (ret == -EIOCBQUEUED)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}

ssize_t
generic_file_write_nolock(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	ret = generic_file_aio_write_nolock(&kiocb, iov, nr_segs, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}
EXPORT_SYMBOL(generic_file_write_nolock);

ssize_t generic_file_aio_write(struct kiocb *iocb, const char __user *buf,
			       size_t count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };

	BUG_ON(iocb->ki_pos != pos);

	/* ��ȡ�ڵ���ź��� */
	down(&inode->i_sem);
	/* ����ʵ�ʵı������ */
	ret = __generic_file_aio_write_nolock(iocb, &local_iov, 1,
						&iocb->ki_pos);
	up(&inode->i_sem);/* �ͷ��ź��� */

	/* �����Ҫ������ͬ��������  */
	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;

		/* ������ˢ�µ����� */
		err = sync_page_range(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_aio_write);

/**
 * ����ļ�ϵͳ(��Ext2��JFS)ͨ����������ʵ���ļ������write������
 * file:		�ļ�����ָ��
 * buf:			�û�̬��ַ�ռ��еĵ�ַ��
 * count:		Ҫд����ַ�������
 * ppos:		����ļ�ƫ�����ı�����ַ����������ƫ��������ʼд�롣
 */
ssize_t generic_file_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	/**
	 * ȷ����д�ļ������ڵ����ĵ�ַinode��
	 */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t	ret;
	/**
	 * ��ʼ��iovec���͵ľֲ��������԰����û�̬�������ĵ�ַ�ͳ��ȡ�
	 */
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };

	/**
	 * ����ļ������ڵ������ź���������һ��ֻ����һ�����̶�ĳ���ļ�����write���á�
	 */
	down(&inode->i_sem);
	ret = __generic_file_write_nolock(file, &local_iov, 1, ppos); /*��*/
	/**
	 * �ͷ��ļ��ź�����
	 */
	up(&inode->i_sem);

	/**
	 * ����ļ���O_SYNC��־�����������ڵ���S_SYNC��־��������MS_SYNCHRONOUS��־
	 */
	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;

		/**
		 * ǿ���ں˽�ҳ���ٻ����е�����ҳˢ�¡�������ǰ����ֱ��IO���ݴ��������
		 */
		err = sync_page_range(inode, mapping, *ppos - ret, ret); /*��*/
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_write);

ssize_t generic_file_readv(struct file *filp, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	ret = __generic_file_aio_read(&kiocb, iov, nr_segs, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}
EXPORT_SYMBOL(generic_file_readv);

ssize_t generic_file_writev(struct file *file, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;

	down(&inode->i_sem);
	ret = __generic_file_write_nolock(file, iov, nr_segs, ppos);
	up(&inode->i_sem);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range(inode, mapping, *ppos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_writev);

/*
 * Called under i_sem for writes to S_ISREG files.   Returns -EIO if something
 * went wrong during pagecache shootdown.
 */
/** 
 * ֱ���ļ���д
 *		rw:		�������ͣ�READ����WRITE��
 *		iocb:	kiocb������ָ�롣
 *		iov:	iovec����������ָ�롣
 *		offset:	�ļ�ƫ������
 *		nr_segs:iov�����е�iovec����������
 */
ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs)
{
	/**
	 * ȡ���ļ�����ĵ�ַ���Լ���ַ�ռ����
	 */
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t retval;

	/*
	 * If it's a write, unmap all mmappings of the file up-front.  This
	 * will cause any pte dirty bits to be propagated into the pageframes
	 * for the subsequent filemap_write_and_wait().
	 */
	/**
	 * �����������ΪWRITE������һ�����߶�������Ѿ����������ļ���ĳ�����ֹ������ڴ�ӳ�䣬�����
	 * unmap_mapping_rangeȡ�����ļ�����ҳ���ڴ�ӳ�䡣����κ�ȡ��ӳ���ҳ����Ӧ��ҳ�����DIRTYλ��Ϊ1����ú���Ҳȷ������ҳ���ٻ����е���Ӧҳ�������Ϊ�ࡣ
	 */
	if (rw == WRITE && mapping_mapped(mapping))
		unmap_mapping_range(mapping, 0, -1, 0); /*��*/

	/**
	 * ���nrpages��Ϊ�գ������filemap_fdatawrite��filemap_fdatawait����ˢ��������ҳ�����̡�
	 * ���ȴ�IO����������
	 * ��ʹ�Ի���Ӧ�ó̶���ֱ�ӷ����ļ��ģ�ϵͳ�л�����ͨ��ҳ���ٻ�������ļ�������Ӧ�ó���
	 * Ϊ�˱������ݵĶ�ʧ��������ֱ��IO����֮ǰ������ӳ��Ҫ��ҳ���ٻ������ͬ����
	 */
	retval = filemap_write_and_wait(mapping); /*��*/
	if (retval == 0) {
		/**
		 * ����mapping��ַ�ռ��direct_io������
		 * ������������  __blockdev_direct_IO()
		 */
		retval = mapping->a_ops->direct_IO(rw, iocb, iov,
						offset, nr_segs); /*��*/
		/**
		 * �������������write�������invalidate_inode_pages2ɨ��mapping����������ҳ���ͷ����ǡ�
		 * ͬʱҲ���ָ����Щҳ���û�̬ҳ���
		 */
		if (rw == WRITE && mapping->nrpages) {
			int err = invalidate_inode_pages2(mapping);
			if (err)
				retval = err;
		}
	}
	return retval;
}
EXPORT_SYMBOL_GPL(generic_file_direct_IO);
