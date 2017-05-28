/*
 * fs/mpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains functions related to preparing and submitting BIOs which contain
 * multiple pagecache pages.
 *
 * 15May2002	akpm@zip.com.au
 *		Initial version
 * 27Jun2002	axboe@suse.de
 *		use bio_add_page() to build bio's just the right size
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
/**
 * mpage_readpage��bio����ɷ�������IO���ݴ������ʱ����������
 * ���û��IO����������ҳ��������PG_uptodate������unlock_page������ҳ�棬�����ѵȴ����¼��Ľ��̡�
 * ������bio_put�����bio��������
 */
static int mpage_end_io_read(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	if (bio->bi_size)
		return 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (uptodate) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	} while (bvec >= bio->bi_io_vec);
	bio_put(bio);
	return 0;
}

static int mpage_end_io_write(struct bio *bio, unsigned int bytes_done, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec = bio->bi_io_vec + bio->bi_vcnt - 1;

	if (bio->bi_size)
		return 1;

	do {
		struct page *page = bvec->bv_page;

		if (--bvec >= bio->bi_io_vec)
			prefetchw(&bvec->bv_page->flags);

		if (!uptodate)
			SetPageError(page);
		end_page_writeback(page);
	} while (bvec >= bio->bi_io_vec);
	bio_put(bio);
	return 0;
}

struct bio *mpage_bio_submit(int rw, struct bio *bio)
{
	bio->bi_end_io = mpage_end_io_read;
	if (rw == WRITE)
		bio->bi_end_io = mpage_end_io_write;
	submit_bio(rw, bio); /*��*/
	return NULL;
}

static struct bio *
mpage_alloc(struct block_device *bdev,
		sector_t first_sector, int nr_vecs, int gfp_flags)
{
	struct bio *bio;

	bio = bio_alloc(gfp_flags, nr_vecs);

	if (bio == NULL && (current->flags & PF_MEMALLOC)) {
		while (!bio && (nr_vecs /= 2))
			bio = bio_alloc(gfp_flags, nr_vecs);
	}

	if (bio) {
		bio->bi_bdev = bdev;
		bio->bi_sector = first_sector;
	}
	return bio;
}

/*
 * support function for mpage_readpages.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_CACHE_SHIFT && 
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, 1 << inode->i_blkbits, 0);
	}
	head = page_buffers(page);
	page_bh = head;
	do {
		if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}

/**
 * mpage_readpages - populate an address space with some pages, and
 *                       start reads against them.
 *
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 *
 *   The page at @pages->prev has the lowest file offset, and reads should be
 *   issued in @pages->prev to @pages->next order.
 *
 * @nr_pages: The number of pages at *@pages
 * @get_block: The filesystem's block mapper function.
 *
 * This function walks the pages and the blocks within each page, building and
 * emitting large BIOs.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_CACHE_SIZE setups.
 *
 * BH_Boundary explanation:
 *
 * There is a problem.  The mpage read code assembles several pages, gets all
 * their disk mappings, and then submits them all.  That's fine, but obtaining
 * the disk mappings may require I/O.  Reads of indirect blocks, for example.
 *
 * So an mpage read of the first 16 blocks of an ext2 file will cause I/O to be
 * submitted in the following order:
 * 	12 0 1 2 3 4 5 6 7 8 9 10 11 13 14 15 16
 * because the indirect block has to be read to get the mappings of blocks
 * 13,14,15,16.  Obviously, this impacts performance.
 * 
 * So what we do it to allow the filesystem's get_block() function to set
 * BH_Boundary when it maps block 11.  BH_Boundary says: mapping of the block
 * after this one will require I/O against a block which is probably close to
 * this one.  So you should push what I/O you have currently accumulated.
 *
 * This all causes the disk requests to be issued in the correct order.
 */
/**
 * �Դ�����ļ���˵������������readpage��ʵ�ַ�����
 */
static struct bio *
do_mpage_readpage(struct bio *bio, struct page *page, unsigned nr_pages,
			sector_t *last_block_in_bio, get_block_t get_block)
{
	struct inode *inode = page->mapping->host;

	/**
	 * �õ���Ĵ�С
	 */
	const unsigned blkbits = inode->i_blkbits;
	/**
	 * ����ҳ�еĿ���
	 */
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	/*
	 * ��һ���ն�Ĭ��Ϊÿҳ�����һ���ļ���������Ҳ����˵��Ĭ��û�пն�
	 */
	unsigned first_hole = blocks_per_page; 
	struct block_device *bdev = NULL;
	struct buffer_head bh;
	int length;
	int fully_mapped = 1;

	/**
	 * ���page��PG_private��־������ñ�־����λ�����ҳ�ǻ�����ҳ����ʾ��ҳ�Ѿ��Ӵ����϶����������ҳ�еĿ��ڴ����ϲ������ڵ�(��Ϊ��������ڵģ���ôǰ������������ˣ����ﲻ���ٶ���ҳ��)��
	 * �����һ�ζ�һ��ķ�ʽ��ȡ��ҳ������confused
	 */
	if (page_has_buffers(page))
		goto confused;

	/**
	 * ҳ�е�һ����ļ���ţ�Ҳ����������ļ���ʼλ�ø�ҳ�е�һ��������
	 *
	 * ����Ĺ�ʽ�ȼ���: page_index * ((PAGE_SIZE) / (blk_size))
	 * PAGE_SIZE = 2^12
	 * blk_size = 2^blkbits
	 * ((PAGE_SIZE) / (blk_size)) => ÿ��ҳ�к��ж��ٿ�
	 * page_index * ((PAGE_SIZE) / (blk_size)) => page_index��ҳǰ���Ѿ����˶��ٸ��飬Ҳ����page_indexҳ�е�һ���ļ����������
	 */
	block_in_file = page->index << (PAGE_CACHE_SHIFT - blkbits); 
	/**
	 * �������һ���ļ�������
	 */
	last_block = (i_size_read(inode) + blocksize - 1) >> blkbits;

	bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page;
				page_block++, block_in_file++) {
		bh.b_state = 0;
		
		if (block_in_file < last_block) {
			/**
			 * ����get_block�õ��߼���ţ�������ڴ��̻������ʼλ�õĿ�������
			 * ҳ��ÿһ����߼���(bh.b_blocknr)�����һ����������(blocks)�С�
			 *
			 * ����ҳ�е�ÿһ�飬�����������ļ�ϵͳ��get_block��������Ϊ�������ݹ�ȥ�õ��߼���ţ�
			 * ������ڴ��̻������ʼλ�õĿ�������ҳ�����п���߼����(bh.b_blocknr)�����һ����������(blocks)�С�
			 */
			if (get_block(inode, block_in_file, &bh, 0))
				goto confused;
		}


		/**
		 * �����������쳣���ʱ������һ�ζ�ȡһ��ķ�ʽ����ҳ:
		 *     һЩ���ڴ����ϲ����ڡ�
		 *     ĳЩ�����ļ����С�
		 * ת�Ƶ�confused��Ǵ�
		 */


		/*
		 * ���ֿն�����¼��һ���ն���page_block��,����ǲ���fully_mapped��˵���пն��������һ��ҳ��û��ӳ����
		 *
		 * ���ҳ�������һ��������continueֱ���˳�forѭ����������ת��confused��Ǵ�
		 */
		if (!buffer_mapped(&bh)) {
			fully_mapped = 0;
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			continue;
		}

		/* some filesystems will copy data into the page during
		 * the get_block call, in which case we don't want to
		 * read it again.  map_buffer_to_page copies the data
		 * we just collected from get_block into the page's buffers
		 * so readpage doesn't have to repeat the get_block call
		 */
		if (buffer_uptodate(&bh)) {
			map_buffer_to_page(page, &bh, page_block);
			goto confused;
		}

	    /*
	     * �����˿ն�����ת��confused��Ǵ�
		 */
		if (first_hole != blocks_per_page)
			goto confused;		/* hole -> non-hole */

		/* Contiguous blocks? */
		/*
		 * ���̿鲻��������ת��confused��Ǵ�
		 *
		 * blocks[page_block]��¼�˵�ǰ���̶�Ӧ���߼����bh.b_blocknr
		 * blocks[page_block-1] ��¼����һ���߼��ţ����������bh.b_blocknr-1��˵���������߼��鲻����
		 */
		if (page_block && blocks[page_block-1] != bh.b_blocknr-1)
			goto confused;
		blocks[page_block] = bh.b_blocknr;
		bdev = bh.b_bdev;
	}

	/**
	 * ���е��ˣ�˵��ҳ�е����п��ڴ����������ڵġ�
	 */
	if (first_hole != blocks_per_page) {
		/**
		 * ���ҳ���ļ��е����һҳ��ĳЩ���ڴ�����û��ӳ�񡣽���Ӧ�Ŀ黺��������0.
		 * Ҳ����˵�ļ����ˣ�ҳû�������ɣ�ҳ�л��п��ಿ�֣������ಿ�����0
		 */
		char *kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + (first_hole << blkbits), 0,
				PAGE_CACHE_SIZE - (first_hole << blkbits));
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
		if (first_hole == 0) {
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {
		/**
		 * �����ļ������һҳ����ҳ�������ı�־PG_mappedtodisk��λ��
		 */
		SetPageMappedToDisk(page);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && (*last_block_in_bio != blocks[0] - 1))
		bio = mpage_bio_submit(READ, bio);

alloc_new:
	/* 
	 * ����mpage_alloc����һ��bio������ʼ���� 
	 * �ֱ��ÿ��豸��������ַ��ҳ�е�һ������߼��������ʼ��bi_dev��bi_sector�ֶ�
	 *
	 * blocks[0] << (blkbits - 9)
	 * => (blocks[0] * (2^blkbits))/ (2^9)
	 * => (�߼���ǰ������е��߼�����Ŀ) / (ÿ��secotr���߼�����)
	 * => ��һ���߼������ڵ�sector������
	 */
	if (bio == NULL) {
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
			  	min_t(int, nr_pages, bio_get_nr_vecs(bdev)),
				GFP_KERNEL);
		if (bio == NULL)
			goto confused;
	}

	length = first_hole << blkbits;
	/*
	 * ��ҳ����ʼ��ַ���������ݵ����ֽ�ƫ����(0)�����������ֽ�����������bio�ε�bio_vec������
	 */
	if (bio_add_page(bio, page, length, 0) < length) {
		bio = mpage_bio_submit(READ, bio);
		goto alloc_new;
	}

	/**
	 * �������ύbio����
	 * ͨ��mpage_bio_submit��mpage_end_io_read�����ĵ�ַ��ֵ��bio->bi_end_io�ֶ�
	 * ����submit_bio�����������ݴ���ķ����趨bi_rw��־������ÿCPU����page_states����������������
	 * ����bio�������ϵ���generic_make_request ִ�������Ĺ���
	 */
	if (buffer_boundary(&bh) || (first_hole != blocks_per_page))
		bio = mpage_bio_submit(READ, bio); /*��*/
	else
		*last_block_in_bio = blocks[blocks_per_page - 1];
out:
	/*
	 * �ɹ�����0
	 */
	return bio;

/**
 * �������е������ҳ�к��еĿ��ڴ��̲�������
 */
confused:
	if (bio)
		bio = mpage_bio_submit(READ, bio);
	if (!PageUptodate(page))
		/**
		 * ҳ�������µģ������block_read_full_pageһ�ζ�һ��ķ�ʽ����ҳ��
		 */
	    block_read_full_page(page, get_block);
	else
		/**
		 * ���ҳ�����µ�(PG_uptodate��λ)�������unlock_page���Ը�ҳ������
		 */
		unlock_page(page);
	goto out;
}

int
mpage_readpages(struct address_space *mapping, struct list_head *pages,
				unsigned nr_pages, get_block_t get_block)
{
	struct bio *bio = NULL;
	unsigned page_idx;
	sector_t last_block_in_bio = 0;
	struct pagevec lru_pvec;

	pagevec_init(&lru_pvec, 0);
	for (page_idx = 0; page_idx < nr_pages; page_idx++) {
		struct page *page = list_entry(pages->prev, struct page, lru);

		prefetchw(&page->flags);
		list_del(&page->lru);
		if (!add_to_page_cache(page, mapping,
					page->index, GFP_KERNEL)) {
			bio = do_mpage_readpage(bio, page,
					nr_pages - page_idx,
					&last_block_in_bio, get_block);
			if (!pagevec_add(&lru_pvec, page))
				__pagevec_lru_add(&lru_pvec);
		} else {
			page_cache_release(page);
		}
	}
	pagevec_lru_add(&lru_pvec);
	BUG_ON(!list_empty(pages));
	if (bio)
		mpage_bio_submit(READ, bio);
	return 0;
}
EXPORT_SYMBOL(mpage_readpages);

/*
 * This isn't called much at all
 */
/**
 * �Դ�����ļ���˵����address_space�����readpage����һ�㶼��mpage_readpage�ķ�װ������
 *
 * get_block���������û������ײ�������й���Ҫ��Ϣ
 * mpage_readpage�ڴ��̶���һҳʱ��ѡ�����ֲ�ͬ�Ĳ��ԣ���������������ݵĿ��ڴ������������ģ���ô�������õ���bio��������ͨ�ÿ�㷢����IO������������������ģ������Ͷ�ҳ�ϵ�ÿһ�����ò�ͬ��bio������������
 * get_block�������ļ�ϵͳ��һ����Ҫ�����þ���: ȷ���ļ��е���һ�����ڴ������Ƿ�Ҳ����һ����
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;

	/* ִ�о���Ĺ��� */
	bio = do_mpage_readpage(bio, page, 1,
			&last_block_in_bio, get_block); /*��*/
	if (bio)/* do_mpage_readpage����δ�ύ��bio���������ύ�� */
		mpage_bio_submit(READ, bio); /*��*/
	return 0;
}
EXPORT_SYMBOL(mpage_readpage);

/*
 * Writing is not so simple.
 *
 * If the page has buffers then they will be used for obtaining the disk
 * mapping.  We only support pages which are fully mapped-and-dirty, with a
 * special case for pages which are unmapped at the end: end-of-file.
 *
 * If the page has no buffers (preferred) then the page is mapped here.
 *
 * If all blocks are found to be contiguous then the page can go into the
 * BIO.  Otherwise fall back to the mapping's writepage().
 * 
 * FIXME: This code wants an estimate of how many pages are still to be
 * written, so it can intelligently allocate a suitably-sized BIO.  For now,
 * just allocate full-size (16-page) BIOs.
 */
/**
 * ������־���ļ�ϵͳ������mpage_writepage�������Զ����writepage������
 * �������Ը������ܣ���Ϊmpage_writepage�����ڽ���IO����ʱ����ͬһ��bio�������оۼ������ܶ��ҳ��
 * ���ʹ�ÿ��豸���������������ִ�Ӳ�̿�������DMA��ɢ���ۼ�������
 */
static struct bio *
mpage_writepage(struct bio *bio, struct page *page, get_block_t get_block,
	sector_t *last_block_in_bio, int *ret, struct writeback_control *wbc)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	unsigned long end_index;
	const unsigned blocks_per_page = PAGE_CACHE_SIZE >> blkbits;
	sector_t last_block;
	sector_t block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_unmapped = blocks_per_page;
	struct block_device *bdev = NULL;
	int boundary = 0;
	sector_t boundary_block = 0;
	struct block_device *boundary_bdev = NULL;
	int length;
	struct buffer_head map_bh;
	loff_t i_size = i_size_read(inode);

    /*
     * ��дҳ������Ŀ��ڴ������Ƿ�����
     * ��ҳ�Ƿ�����ļ��ն�
     * ҳ�ϵ�ĳ���Ƿ�û������߲������µ�
     * ��������������һ��������������������������Ȼ�������ļ�ϵͳ��writepage��������confused��
     */
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		/* If they're all mapped and dirty, do it */
		page_block = 0;
		do {
			BUG_ON(buffer_locked(bh));
			if (!buffer_mapped(bh)) {
				/*
				 * unmapped dirty buffers are created by
				 * __set_page_dirty_buffers -> mmapped data
				 */
				if (buffer_dirty(bh))
					goto confused;
				if (first_unmapped == blocks_per_page)
					first_unmapped = page_block;
				continue;
			}

			if (first_unmapped != blocks_per_page)
				goto confused;	/* hole -> non-hole */

			if (!buffer_dirty(bh) || !buffer_uptodate(bh))
				goto confused;
			if (page_block) {
				if (bh->b_blocknr != blocks[page_block-1] + 1)
					goto confused;
			}
			blocks[page_block++] = bh->b_blocknr;
			boundary = buffer_boundary(bh);
			if (boundary) {
				boundary_block = bh->b_blocknr;
				boundary_bdev = bh->b_bdev;
			}
			bdev = bh->b_bdev;
		} while ((bh = bh->b_this_page) != head);

		if (first_unmapped)
			goto page_is_mapped;

		/*
		 * Page has buffers, but they are all unmapped. The page was
		 * created by pagein or read over a hole which was handled by
		 * block_read_full_page().  If this address_space is also
		 * using mpage_readpages then this can rarely happen.
		 */
		goto confused;
	}

	/*
	 * The page has no buffers: map it to disk
	 */
	BUG_ON(!PageUptodate(page));
	block_in_file = page->index << (PAGE_CACHE_SHIFT - blkbits); /*(PAGE_CACHE_SHIFT - blkbits)ÿҳ�еĿ�����������ʵ�ǳ���;��������ļ�д��λ��ǰ���ж��ٸ���*/
	last_block = (i_size - 1) >> blkbits; /*���һ����ı�� = �ļ��Ŀ��� = (�ļ���С / ÿ���С) */
	map_bh.b_page = page;
	for (page_block = 0; page_block < blocks_per_page; ) {

		map_bh.b_state = 0;
		if (get_block(inode, block_in_file, &map_bh, 1))
			goto confused;
		if (buffer_new(&map_bh))
			unmap_underlying_metadata(map_bh.b_bdev,
						map_bh.b_blocknr);
		if (buffer_boundary(&map_bh)) {
			boundary_block = map_bh.b_blocknr;
			boundary_bdev = map_bh.b_bdev;
		}
		if (page_block) {
			if (map_bh.b_blocknr != blocks[page_block-1] + 1)
				goto confused;
		}
		blocks[page_block++] = map_bh.b_blocknr;
		boundary = buffer_boundary(&map_bh);
		bdev = map_bh.b_bdev;
		if (block_in_file == last_block)
			break;
		block_in_file++;
	}
	BUG_ON(page_block == 0);

	first_unmapped = page_block;

page_is_mapped:
	end_index = i_size >> PAGE_CACHE_SHIFT;
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invokation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_CACHE_SIZE - 1);
		char *kaddr;

		if (page->index > end_index || !offset)
			goto confused;
		kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + offset, 0, PAGE_CACHE_SIZE - offset);
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (bio && *last_block_in_bio != blocks[0] - 1)
		bio = mpage_bio_submit(WRITE, bio);

	/**
	 * ��ҳ׷��Ϊbio�������е�һ�Ρ�
	 */
alloc_new:
	/**
	 * ��������bioΪ�գ��ͳ�ʼ��һ���µ�bio��������ַ��
	 * ���������������ظ����ú��������ú����´ε���mpage_writepageʱ�������������ٴδ��롣
	 * ������ͬһ��bio���Լ��ؼ���ҳ��
	 */
	if (bio == NULL) {
		bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
				bio_get_nr_vecs(bdev), GFP_NOFS|__GFP_HIGH); /*��*/
		if (bio == NULL)
			goto confused;
	}

	/*
	 * Must try to add the page before marking the buffer clean or
	 * the confused fail path above (OOM) will be very confused when
	 * it finds all bh marked clean (i.e. it will not write anything)
	 */
	length = first_unmapped << blkbits; /*first_unmapped�ǵ�һ��Ϊӳ����̵�bh����ôfirst_unmapped << blkbits��δӳ��֮ǰ�Ŀ鳤��*/
	/**
	 * ���bio��ĳҳ����һ������ҳ�����ڣ������mpage_bio_submit��ʼ�µ�IO���ݴ��䡣
	 * Ȼ�����һ���µ�bio��
	 */
	if (bio_add_page(bio, page, length, 0) < length) { /*��*/
		bio = mpage_bio_submit(WRITE, bio); /*��*/
		goto alloc_new;
	}

	/*
	 * OK, we have our BIO, so we can now mark the buffers clean.  Make
	 * sure to only clean buffers which we know we'll be writing.
	 */
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;
		unsigned buffer_counter = 0;

		do {
			if (buffer_counter++ == first_unmapped)
				break;
			clear_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);

		/*
		 * we cannot drop the bh if the page is not uptodate
		 * or a concurrent readpage would fail to serialize with the bh
		 * and it would read from disk before we reach the platter.
		 */
		if (buffer_heads_over_limit && PageUptodate(page))
			try_to_free_buffers(page);
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	if (boundary || (first_unmapped != blocks_per_page)) {
		bio = mpage_bio_submit(WRITE, bio); /*��*/
		if (boundary_block) {
			write_boundary_block(boundary_bdev,
					boundary_block, 1 << blkbits);
		}
	} else {
		*last_block_in_bio = blocks[blocks_per_page - 1];
	}
	goto out;

confused:
    /*�˴����������bio����mpage_bio_submit������������ݴ��䣬���л����submit_bio��������ͨ�ò�*/
	if (bio)
		bio = mpage_bio_submit(WRITE, bio); /*��*/
	*ret = page->mapping->a_ops->writepage(page, wbc);
	/*
	 * The caller has a ref on the inode, so *mapping is stable
	 */
	if (*ret) {
		if (*ret == -ENOSPC)
			set_bit(AS_ENOSPC, &mapping->flags);
		else
			set_bit(AS_EIO, &mapping->flags);
	}
out:
	return bio;
}

/**
 * mpage_writepages - walk the list of dirty pages of the given
 * address space and writepage() all of them.
 * 
 * @mapping: address space structure to write
 * @wbc: subtract the number of written pages from *@wbc->nr_to_write
 * @get_block: the filesystem's block mapper function.
 *             If this is NULL then use a_ops->writepage.  Otherwise, go
 *             direct-to-BIO.
 *
 * This is a library function, which implements the writepages()
 * address_space_operation.
 *
 * If a page is already under I/O, generic_writepages() skips it, even
 * if it's dirty.  This is desirable behaviour for memory-cleaning writeback,
 * but it is INCORRECT for data-integrity system calls such as fsync().  fsync()
 * and msync() need to guarantee that all the data which was dirty at the time
 * the call was made get new I/O started against them.  If wbc->sync_mode is
 * WB_SYNC_ALL then we were called for data integrity and we must wait for
 * existing IO to complete.
 */
/**
 * ����ҳд�ش��̡�
 * pdflush��ͬ��д��Ҫ���á�
 */
int
mpage_writepages(struct address_space *mapping,
		struct writeback_control *wbc, get_block_t get_block)
{
	struct backing_dev_info *bdi = mapping->backing_dev_info;
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	int ret = 0;
	int done = 0;
	int (*writepage)(struct page *page, struct writeback_control *wbc);
	struct pagevec pvec;
	int nr_pages;
	pgoff_t index;
	pgoff_t end = -1;		/* Inclusive */
	int scanned = 0;
	int is_range = 0;

	/**
	 * �������дӵ�������ҽ��̲�ϣ����������ֱ�ӷ��ء�
	 */
	if (wbc->nonblocking && bdi_write_congested(bdi)) {
		wbc->encountered_congestion = 1;
		return 0;
	}

	writepage = NULL;
	if (get_block == NULL)
        /*
         * ����ext2_writepage->block_write_full_page
         */
		writepage = mapping->a_ops->writepage;

	pagevec_init(&pvec, 0);
	/**
	 * ȷ����ҳ�����wbc������ָ���߳�����ȴ�IO���ݴ����������mapping->writeback_index��Ϊ��ʼҳ������
	 * Ҳ����˵������һ��д�ز��������һҳ��ʼɨ�衣
	 */
	if (wbc->sync_mode == WB_SYNC_NONE) {
		index = mapping->writeback_index; /* Start from prev offset */
	} else {
		/**
		 * ���򣬽��̱���ȴ�IO���ݴ�����ϣ����ļ��ĵ�һҳ��ʼɨ�衣
		 */
		index = 0;			  /* whole-file sweep */
		scanned = 1;
	}
    /*
     * ȷ����ҳ�����wbc������������һ���ļ��ڵĳ�ʼλ�ã�����������ת����ҳ����
     */
	if (wbc->start || wbc->end) {
		index = wbc->start >> PAGE_CACHE_SHIFT;
		end = wbc->end >> PAGE_CACHE_SHIFT;
		is_range = 1;
		scanned = 1;
	}
retry:
	/**
	 * pagevec_lookup_tag�����find_get_pages_tag��ҳ���ٻ����в�����ҳ��������
	 */
	while (!done && (index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_DIRTY,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1))) { /*��*/
		unsigned i;

		scanned = 1;
		/**
		 * �����ҵ���ÿ����ҳ��
		 */
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/*
			 * At this point we hold neither mapping->tree_lock nor
			 * lock on the page itself: the page may be truncated or
			 * invalidated (changing page->mapping to NULL), or even
			 * swizzled back from swapper_space to tmpfs file
			 * mapping
			 */
			/**
			 * ����ס��ҳ.
			 */
			lock_page(page);

			/**
			 * ȷ��ҳ����Ч�ģ�����ҳ���ٻ����ڡ�
			 * ������Ϊ����סҳ֮ǰ�������ں˴�����ܲ����˸�ҳ��
			 */
			if (unlikely(page->mapping != mapping)) {
				unlock_page(page);
				continue;
			}

			if (unlikely(is_range) && page->index > end) {
				done = 1;
				unlock_page(page);
				continue;
			}

			/**
			 * ���ҳ��PG_writeback��־�������λ����ʾҳ�Ѿ���ˢ�µ����̡�
			 * �������ȴ�IO���ݴ�����ϣ������wait_on_page_bit��PG_writeback��0֮ǰһֱ������ǰ���̡�
			 */
			if (wbc->sync_mode != WB_SYNC_NONE)
				wait_on_page_writeback(page);

			/** 
			 * ���PG_writeback��־��λ������PG_dirty������ñ�־Ϊ0�����������е�д�ز����������ҳ��������һҳ��
			 */
			if (PageWriteback(page) ||
					!clear_page_dirty_for_io(page)) {
				unlock_page(page);
				continue;
			}

			if (writepage) {
				/**
				 * get_blockΪNULL�������mapping->writepage������ҳˢ�µ����̡�
				 * ����block_write_full_page
				 */
				ret = (*writepage)(page, wbc); /*��*/
				if (ret) {
					if (ret == -ENOSPC)
						set_bit(AS_ENOSPC,
							&mapping->flags);
					else
						set_bit(AS_EIO,
							&mapping->flags);
				}
			} else {
				/**
				 * get_block��ΪNULL,�����mpage_writepageˢ��ҳ�档
				 */
				bio = mpage_writepage(bio, page, get_block,
						&last_block_in_bio, &ret, wbc); /*��*/
			}
			if (ret || (--(wbc->nr_to_write) <= 0))
				done = 1;
			if (wbc->nonblocking && bdi_write_congested(bdi)) {
				wbc->encountered_congestion = 1;
				done = 1;
			}
		}
		pagevec_release(&pvec);
		/**
		 * ����һ�����ȵ㡣
		 */
		cond_resched();
	}
	/**
	 * û��ɨ���������Χ�ڵ�����ҳ������д�����̵���Чҳ��С��wbc�и�����ֵ(done)�������
	 */
	if (!scanned && !done) {
		/*
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		scanned = 1;
		index = 0;
		goto retry;
	}
	/**
	 * ���wbc��û�и����ļ��ڵĳ�ʼλ�ã������һ��ɨ���ҳ����mapping->writeback_index
	 */
	if (!is_range)
		mapping->writeback_index = index;
	/**
	 * ����������ù�mpage_writepage���������ҷ�����bio��������ַ�������mpage_bio_submit
	 */
	if (bio)
		mpage_bio_submit(WRITE, bio); /*��*/
	return ret;
}
EXPORT_SYMBOL(mpage_writepages);
