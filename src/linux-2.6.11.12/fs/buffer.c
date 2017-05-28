/*
 *  linux/fs/buffer.c
 *
 *  Copyright (C) 1991, 1992, 2002  Linus Torvalds
 */

/*
 * Start bdflush() with kernel_thread not syscall - Paul Gortmaker, 12/95
 *
 * Removed a lot of unnecessary code and simplified things now that
 * the buffer cache isn't our primary cache - Andrew Tridgell 12/96
 *
 * Speed up hash, lru, and free list operations.  Use gfp() for allocating
 * hash table, use SLAB cache for buffer heads. SMP threading.  -DaveM
 *
 * Added 32k buffer block sizes - these are required older ARM systems. - RMK
 *
 * async buffer flushing, 1999 Andrea Arcangeli <andrea@suse.de>
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/bitops.h>

static int fsync_buffers_list(spinlock_t *lock, struct list_head *list);
static void invalidate_bh_lrus(void);

#define BH_ENTRY(list) list_entry((list), struct buffer_head, b_assoc_buffers)

inline void
init_buffer(struct buffer_head *bh, bh_end_io_t *handler, void *private)
{
	bh->b_end_io = handler;
	bh->b_private = private;
}

static int sync_buffer(void *word)
{
	struct block_device *bd;
	struct buffer_head *bh
		= container_of(word, struct buffer_head, b_state);

	smp_mb();
	bd = bh->b_bdev;
	if (bd)
		blk_run_address_space(bd->bd_inode->i_mapping);
	io_schedule();
	return 0;
}

void fastcall __lock_buffer(struct buffer_head *bh)
{
	wait_on_bit_lock(&bh->b_state, BH_Lock, sync_buffer,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_buffer);

void fastcall unlock_buffer(struct buffer_head *bh)
{
	clear_buffer_locked(bh);
	smp_mb__after_clear_bit();
	wake_up_bit(&bh->b_state, BH_Lock);
}

/*
 * Block until a buffer comes unlocked.  This doesn't stop it
 * from becoming locked again - you have to lock it yourself
 * if you want to preserve its state.
 */
void __wait_on_buffer(struct buffer_head * bh)
{
	wait_on_bit(&bh->b_state, BH_Lock, sync_buffer, TASK_UNINTERRUPTIBLE);
}

static void
__clear_page_buffers(struct page *page)
{
	ClearPagePrivate(page);
	page->private = 0;
	page_cache_release(page);
}

static void buffer_io_error(struct buffer_head *bh)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_ERR "Buffer I/O error on device %s, logical block %Lu\n",
			bdevname(bh->b_bdev, b),
			(unsigned long long)bh->b_blocknr);
}

/*
 * Default synchronous end-of-IO handler..  Just mark it up-to-date and
 * unlock the buffer. This is what ll_rw_block uses too.
 */
/**
 * ll_rw_block��Ҫ�ѻ������ײ����ݵ�ͨ�ÿ�㣬������������bh�����ü�����
 * ��ô���������IO����󣬾���Ҫ�������ü����������������bh��b_end_io����ɵġ�
 * b_end_io���պ����end_buffer_read_sync����end_buffer_write_sync
 */
void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh); /*��*/
	} else {
		/* This happens, due to failed READA attempts. */
		clear_buffer_uptodate(bh);
	}
	unlock_buffer(bh); /*��*/ 
	put_bh(bh); /*��*/
}

/**
 * ll_rw_block��Ҫ�ѻ������ײ����ݵ�ͨ�ÿ�㣬������������bh�����ü�����
 * ��ô���������IO����󣬾���Ҫ�������ü����������������bh��b_end_io����ɵġ�
 * b_end_io���պ����end_buffer_read_sync����end_buffer_write_sync
 */
void end_buffer_write_sync(struct buffer_head *bh, int uptodate)
{
	char b[BDEVNAME_SIZE];

	if (uptodate) {
		set_buffer_uptodate(bh); /*��*/
	} else {
		if (!buffer_eopnotsupp(bh) && printk_ratelimit()) {
			buffer_io_error(bh);
			printk(KERN_WARNING "lost page write due to "
					"I/O error on %s\n",
				       bdevname(bh->b_bdev, b));
		}
		set_buffer_write_io_error(bh);
		clear_buffer_uptodate(bh);
	}
	unlock_buffer(bh); /*��*/ 
	put_bh(bh); /*��*/
}

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
	int ret = 0;

	if (bdev) {
		int err;

		ret = filemap_fdatawrite(bdev->bd_inode->i_mapping);
		err = filemap_fdatawait(bdev->bd_inode->i_mapping);
		if (!ret)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(sync_blockdev);

/*
 * Write out and wait upon all dirty data associated with this
 * superblock.  Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
int fsync_super(struct super_block *sb)
{
	sync_inodes_sb(sb, 0);
	DQUOT_SYNC(sb);
	lock_super(sb);
	if (sb->s_dirt && sb->s_op->write_super)
		sb->s_op->write_super(sb);
	unlock_super(sb);
	if (sb->s_op->sync_fs)
		sb->s_op->sync_fs(sb, 1);
	sync_blockdev(sb->s_bdev);
	sync_inodes_sb(sb, 1);

	return sync_blockdev(sb->s_bdev);
}

/*
 * Write out and wait upon all dirty data associated with this
 * device.   Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
int fsync_bdev(struct block_device *bdev)
{
	struct super_block *sb = get_super(bdev);
	if (sb) {
		int res = fsync_super(sb);
		drop_super(sb);
		return res;
	}
	return sync_blockdev(bdev);
}

/**
 * freeze_bdev  --  lock a filesystem and force it into a consistent state
 * @bdev:	blockdevice to lock
 *
 * This takes the block device bd_mount_sem to make sure no new mounts
 * happen on bdev until thaw_bdev() is called.
 * If a superblock is found on this device, we take the s_umount semaphore
 * on it to make sure nobody unmounts until the snapshot creation is done.
 */
struct super_block *freeze_bdev(struct block_device *bdev)
{
	struct super_block *sb;

	down(&bdev->bd_mount_sem);
	sb = get_super(bdev);
	if (sb && !(sb->s_flags & MS_RDONLY)) {
		sb->s_frozen = SB_FREEZE_WRITE;
		wmb();

		sync_inodes_sb(sb, 0);
		DQUOT_SYNC(sb);

		lock_super(sb);
		if (sb->s_dirt && sb->s_op->write_super)
			sb->s_op->write_super(sb);
		unlock_super(sb);

		if (sb->s_op->sync_fs)
			sb->s_op->sync_fs(sb, 1);

		sync_blockdev(sb->s_bdev);
		sync_inodes_sb(sb, 1);

		sb->s_frozen = SB_FREEZE_TRANS;
		wmb();

		sync_blockdev(sb->s_bdev);

		if (sb->s_op->write_super_lockfs)
			sb->s_op->write_super_lockfs(sb);
	}

	sync_blockdev(bdev);
	return sb;	/* thaw_bdev releases s->s_umount and bd_mount_sem */
}
EXPORT_SYMBOL(freeze_bdev);

/**
 * thaw_bdev  -- unlock filesystem
 * @bdev:	blockdevice to unlock
 * @sb:		associated superblock
 *
 * Unlocks the filesystem and marks it writeable again after freeze_bdev().
 */
void thaw_bdev(struct block_device *bdev, struct super_block *sb)
{
	if (sb) {
		BUG_ON(sb->s_bdev != bdev);

		if (sb->s_op->unlockfs)
			sb->s_op->unlockfs(sb);
		sb->s_frozen = SB_UNFROZEN;
		wmb();
		wake_up(&sb->s_wait_unfrozen);
		drop_super(sb);
	}

	up(&bdev->bd_mount_sem);
}
EXPORT_SYMBOL(thaw_bdev);

/*
 * sync everything.  Start out by waking pdflush, because that writes back
 * all queues in parallel.
 */
/*
 * syncϵͳ���õ�ʵ�ֺ�����
 */
static void do_sync(unsigned long wait)
{
	/**
	 * ����pdflush�ں��̡߳���������ҳд�뵽���̡�
	 */
	wakeup_bdflush(0);
	/**
	 * ɨ�賬���������������Ҫˢ�µ��������ڵ㡣
	 * �����ڲ���wait, �ò�����ʾ��ִ����ˢ��֮ǰ�����Ƿ����ȴ�
	 */
	sync_inodes(0);		/* All mappings, inodes and their blockdevs */
	DQUOT_SYNC(NULL);
	/**
	 * ���೬����д�����̡�
	 */
	sync_supers();		/* Write the superblocks */
	/**
	 * Ϊ���п�д���ļ�ϵͳִ��sync_fs�����鷽����
	 * �����ļ�ϵͳ��һ�����ӣ�����Ҫ��ÿ��ͬ��ִ��һЩ�������ʱʹ�ã���ext3��������־�ļ�ϵͳʹ�����������
	 */
	sync_filesystems(0);	/* Start syncing the filesystems */
	/**
	 * sync_filesystems��sync_inodes���ٴε��á�
	 * �����������Ĳ������˱仯��һ��wait ����0��һ�ε���1
	 * ��������Ŀ����: 
	 * ���ȣ����ǰ�δ�����������ڵ���ٵ�ˢ�µ����̣���Σ����ǵȴ����������������ڵ㱻������Ȼ����������д������
	 */
	sync_filesystems(wait);	/* Waitingly sync the filesystems */
	sync_inodes(wait);	/* Mappings, inodes and blockdevs, again. */
	if (!wait)
		printk("Emergency Sync complete\n");
	if (unlikely(laptop_mode))
		laptop_sync_completion();
}

/**
 * syncϵͳ���õ�ʵ�ֺ�����
 */
asmlinkage long sys_sync(void)
{
	do_sync(1);
	return 0;
}

void emergency_sync(void)
{
	pdflush_operation(do_sync, 0);
}

/*
 * Generic function to fsync a file.
 *
 * filp may be NULL if called via the msync of a vma.
 */
 
int file_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	struct inode * inode = dentry->d_inode;
	struct super_block * sb;
	int ret, err;

	/* sync the inode to buffers */
	ret = write_inode_now(inode, 0);

	/* sync the superblock to buffers */
	sb = inode->i_sb;
	lock_super(sb);
	if (sb->s_op->write_super)
		sb->s_op->write_super(sb);
	unlock_super(sb);

	/* .. finally sync the buffers to disk */
	err = sync_blockdev(sb->s_bdev);
	if (!ret)
		ret = err;
	return ret;
}

/**
 * ϵͳ����fsync��ʵ�֡�
 * ��fd��Ӧ�������໺����д�������У������Ҫ�����������������ڵ�Ļ�������
 */
asmlinkage long sys_fsync(unsigned int fd)
{
	struct file * file;
	struct address_space *mapping;
	int ret, err;

	ret = -EBADF;
	/**
	 * ����ļ�����ĵ�ַ��
	 */
	file = fget(fd); /*��*/
	if (!file)
		goto out;

	mapping = file->f_mapping;

	ret = -EINVAL;
	if (!file->f_op || !file->f_op->fsync) {
		/* Why?  We can still call filemap_fdatawrite */
		goto out_putf;
	}

	current->flags |= PF_SYNCWRITE;
	ret = filemap_fdatawrite(mapping);

	/*
	 * We need to protect against concurrent writers,
	 * which could cause livelocks in fsync_buffers_list
	 */
	down(&mapping->host->i_sem);
	/**
	 * �����ļ������fsync������������ͬ����
	 * �ûص�����ͨ�����Ե���__writeback_single_inode  �����������ú������뱻ѡ�е������ڵ���ص���ҳ�������ڵ㱾��д�ش���
	 */
	err = file->f_op->fsync(file, file->f_dentry, 0); /*��*/
	if (!ret)
		ret = err;
	up(&mapping->host->i_sem);
	err = filemap_fdatawait(mapping);
	if (!ret)
		ret = err;
	current->flags &= ~PF_SYNCWRITE;

out_putf:
	fput(file);
out:
	return ret;
}

/*
 * fdatasync ���ŷ�����
 * ��fsync()�ǳ����ƣ����ǲ�ˢ���ļ��������ڵ��
 * Linux2.6û���ṩר�ŵ�fdatasync()�ļ���������ϵͳ����ʹ��fsync�����������fsync()����ͬ��
 */
asmlinkage long sys_fdatasync(unsigned int fd)
{
	struct file * file;
	struct address_space *mapping;
	int ret, err;

	ret = -EBADF;
	file = fget(fd); /*��*/
	if (!file)
		goto out;

	ret = -EINVAL;
	if (!file->f_op || !file->f_op->fsync)
		goto out_putf;

	mapping = file->f_mapping;

	current->flags |= PF_SYNCWRITE;
	ret = filemap_fdatawrite(mapping);
	down(&mapping->host->i_sem);
	err = file->f_op->fsync(file, file->f_dentry, 1); /*��*/
	if (!ret)
		ret = err;
	up(&mapping->host->i_sem);
	err = filemap_fdatawait(mapping);
	if (!ret)
		ret = err;
	current->flags &= ~PF_SYNCWRITE;

out_putf:
	fput(file);
out:
	return ret;
}

/*
 * Various filesystems appear to want __find_get_block to be non-blocking.
 * But it's the page lock which protects the buffers.  To get around this,
 * we get exclusion from try_to_free_buffers with the blockdev mapping's
 * private_lock.
 *
 * Hack idea: for the blockdev mapping, i_bufferlist_lock contention
 * may be quite high.  This code could TryLock the page, and if that
 * succeeds, there is no need to take private_lock. (But if
 * private_lock is contended then so is mapping->tree_lock).
 */
/**
 * �ڸ��ٻ����������������ײ���
 */
static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block, int unused)
{
	struct inode *bd_inode = bdev->bd_inode;
	struct address_space *bd_mapping = bd_inode->i_mapping;
	struct buffer_head *ret = NULL;
	pgoff_t index;
	struct buffer_head *bh;
	struct buffer_head *head;
	struct page *page;
	int all_mapped = 1;

	/**
	 * ���ݿ�źͿ��С�õ�����豸��ص�ҳ�������㷨���Ͳμ�P614�ĵڶ���
	 * 
	 * PAGE_CACHE_SHIFT == PAGE_SHIFT, 
	 * һҳ��С = 2 ^ PAGE_SHIFT
	 * һ���С = 2 ^ bd_inode->i_blkbits
	 * ҳ���� = block / ÿҳ�ϵĿ��� 
	 *        = block / (һҳ��С / һ���С) 
	 *        = block / (2 ^ (PAGE_CACHE_SHIFT - bd_inode->i_blkbits)) 
	 *        = block >> (PAGE_CACHE_SHIFT - bd_inode->i_blkbits);
	 * ҳ��������ָ��������ҳ��������ţ�����ҳ�����ҵ���Ӧ��ҳ�棬
	 * �ٴ�ҳ���bh������ͨ��block�ҵ���Ӧ�Ŀ��bh��
	 * ����ҳ����ֻ��ȷ���鲻��ȷ��Ҳ��
	 * Ҳ����һ��ҳ�������ܶ�Ӧ4����ţ���4�����bh��ͬһ��ҳ�У�ҳ������ͬ
	 */
	index = block >> (PAGE_CACHE_SHIFT - bd_inode->i_blkbits);
	/**
	 * ����find_get_pageȷ������Ŀ黺����ҳ�Ļ���ҳ���ٻ����е�λ�á�
	 */
	page = find_get_page(bd_mapping, index);

	/**
	 * ҳû���ڸ��ٻ����У���Ҳ��Ȼ���ڸ��ٻ����С�
	 */
	if (!page)
		goto out;

	spin_lock(&bd_mapping->private_lock);
    /*
     * ҳ�Ѿ���ҳ���ٻ����С��������PG_private��־��
     */
	if (!page_has_buffers(page))
		goto out_unlock;
    /*
     * ��ҳ��������private�ֶλ�õ�һ���������ײ��ĵ�ַbh��
     */    
	head = page_buffers(page);
	bh = head;
	/**
	 * ��ҳ�Ļ������ײ������������߼���ŵ���block�Ŀ顣
	 */
	do {
        /*
         * ע�����ﲻ�ñȽ�b_bdev�Ƿ����bdev,
         * ����Ϊ�û�����ҳ����bdev��bd_inode->i_mapping���ҵ��ģ�
         * bh���ڻ�����ҳ������bh�ض����ڸ�bdev
         */
		if (bh->b_blocknr == block) {
			ret = bh;
			get_bh(bh);
			goto out_unlock;
		}
		if (!buffer_mapped(bh))
			all_mapped = 0;
		bh = bh->b_this_page;
	} while (bh != head);

	/* we might be here because some of the buffers on this page are
	 * not mapped.  This is due to various races between
	 * file io on the block device and getblk.  It gets dealt with
	 * elsewhere, don't buffer_error if we had some unmapped buffers
	 */
	if (all_mapped) {
		printk("__find_get_block_slow() failed. "
			"block=%llu, b_blocknr=%llu\n",
			(unsigned long long)block, (unsigned long long)bh->b_blocknr);
		printk("b_state=0x%08lx, b_size=%u\n", bh->b_state, bh->b_size);
		printk("device blocksize: %d\n", 1 << bd_inode->i_blkbits);
	}
out_unlock:
	spin_unlock(&bd_mapping->private_lock);
	/**
	 * �ݼ���������count�ֶ�(find_get_page����������ֵ)��
	 */
	page_cache_release(page);
out:
	return ret;
}

/* If invalidate_buffers() will trash dirty buffers, it means some kind
   of fs corruption is going on. Trashing dirty data always imply losing
   information that was supposed to be just stored on the physical layer
   by the user.

   Thus invalidate_buffers in general usage is not allwowed to trash
   dirty buffers. For example ioctl(FLSBLKBUF) expects dirty data to
   be preserved.  These buffers are simply skipped.
  
   We also skip buffers which are still in use.  For example this can
   happen if a userspace program is reading the block device.

   NOTE: In the case where the user removed a removable-media-disk even if
   there's still dirty data not synced on disk (due a bug in the device driver
   or due an error of the user), by not destroying the dirty buffers we could
   generate corruption also on the next media inserted, thus a parameter is
   necessary to handle this case in the most safe way possible (trying
   to not corrupt also the new disk inserted with the data belonging to
   the old now corrupted disk). Also for the ramdisk the natural thing
   to do in order to release the ramdisk memory is to destroy dirty buffers.

   These are two special cases. Normal usage imply the device driver
   to issue a sync on the device (without waiting I/O completion) and
   then an invalidate_buffers call that doesn't trash dirty buffers.

   For handling cache coherency with the blkdev pagecache the 'update' case
   is been introduced. It is needed to re-read from disk any pinned
   buffer. NOTE: re-reading from disk is destructive so we can do it only
   when we assume nobody is changing the buffercache under our I/O and when
   we think the disk contains more recent information than the buffercache.
   The update == 1 pass marks the buffers we need to update, the update == 2
   pass does the actual I/O. */
void invalidate_bdev(struct block_device *bdev, int destroy_dirty_buffers)
{
	invalidate_bh_lrus();
	/*
	 * FIXME: what about destroy_dirty_buffers?
	 * We really want to use invalidate_inode_pages2() for
	 * that, but not until that's cleaned up.
	 */
	invalidate_inode_pages(bdev->bd_inode->i_mapping);
}

/*
 * Kick pdflush then try to free up some ZONE_NORMAL memory.
 */
/**
 * �ڴ��ȱ���ա��ڷ���VFS�������򻺳����ײ�ʱ���ں˵��ô˺�����
 */
static void free_more_memory(void)
{
	struct zone **zones;
	pg_data_t *pgdat;

	/**
	 * ����pdflush��������ҳ���ٻ�����1024����ҳ��д������
	 * д��ҳ�����̵Ĳ���������ʹ�������������������ײ�������VFS���ݽṹ��ҳ���Ϊ���ͷŵġ�
	 */
	wakeup_bdflush(1024);
	/**
	 * ����yieldʹpdflush�ں��߳��ܹ��л���õ�ִ�С�
	 */
	yield();

	/**
	 * ��ϵͳ�������ڴ�ڵ㣬����һ��ѭ����
	 * NUMA��ÿ���ڴ�ڵ�ʹ��pgdat
	 */
	for_each_pgdat(pgdat) {
		zones = pgdat->node_zonelists[GFP_NOFS&GFP_ZONEMASK].zones;
		/**
		 * ��ÿ���ڵ㣬����try_to_free_pages������ȱ�ڴ������������Ϊ������
		 */
		if (*zones)
			try_to_free_pages(zones, GFP_NOFS, 0);
	}
}

/*
 * I/O completion handler for block_read_full_page() - pages
 * which come unlocked at the end of I/O.
 */
/**
 * �ǻ������ײ�����ɷ������Կ黺������IO���ݴ���һ����������ִ�С�
 * ����block_read_full_page��I/O��ɴ�������
 */
static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	static DEFINE_SPINLOCK(page_uptodate_lock);
	unsigned long flags;
	struct buffer_head *tmp;
	struct page *page;
	int page_uptodate = 1;

	/* ��block_read_full_page��Ӧ�������˴˱�־���ڴ�ȷ�� */
	BUG_ON(!buffer_async_read(bh));

    /*
     * �õ������������Ļ�����ҳ��������
	 */
	page = bh->b_page;
	if (uptodate) {/* IOִ�гɹ�������uptodate��־ */
		set_buffer_uptodate(bh);
	} else {
		/* ��������ҳ������־ */
		clear_buffer_uptodate(bh);
		if (printk_ratelimit())
			buffer_io_error(bh);
		SetPageError(page);
	}

	/*
	 * Be _very_ careful from here on. Bad things can happen if
	 * two buffer heads end IO at almost the same time and both
	 * decide that the page is now completely done.
	 */
	spin_lock_irqsave(&page_uptodate_lock, flags);
	/*
	 * ���������ײ���BH_Async_Read��־��0
	 */
	clear_buffer_async_read(bh);
	unlock_buffer(bh);
	tmp = bh;
	/*
	 * ����Ƿ�ҳ�����п������µģ�����ǣ���������ҳ��PG_uptodate��־��λ������unlock_page()
	 */
	do {/* ѭ�����ҳ���е����л������ײ� */
		if (!buffer_uptodate(tmp))/* ĳ���������ײ���û�и��£������ҳ��uptodate��־ */
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {/* ĳ����������û����ɣ���Ȼ����BH_Async_Read��־ */
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;/* ����ҳ�滹û����ɣ��˳��������л������ײ�����ɺ��ټ��� */
		}
		tmp = tmp->b_this_page;
	} while (tmp != bh);
	spin_unlock_irqrestore(&page_uptodate_lock, flags);

	/*
	 * If none of the buffers had errors and they are all
	 * uptodate then we can set the page uptodate.
	 */
	if (page_uptodate && !PageError(page))/* ����ҳ�涼����ˣ�����û�д��� */
		SetPageUptodate(page);/* ����ҳ����±�־ */
	/* ����ҳ�� */
	unlock_page(page);
	return;

still_busy:
	spin_unlock_irqrestore(&page_uptodate_lock, flags);
	return;
}

/*
 * Completion handler for block_write_full_page() - pages which are unlocked
 * during I/O, and which have PageWriteback cleared upon I/O completion.
 */
/* �黺�������ɹ�д����̺�,�ص��˺��� */
void end_buffer_async_write(struct buffer_head *bh, int uptodate)
{
	char b[BDEVNAME_SIZE];
	static DEFINE_SPINLOCK(page_uptodate_lock);
	unsigned long flags;
	struct buffer_head *tmp;
	struct page *page;

	/* ��block_write_full_page�����У�Ϊ��������˴˱�־���������־�������ڴ淽������� */
	BUG_ON(!buffer_async_write(bh));

	page = bh->b_page;
	if (uptodate) {/* �ɹ���д������uptodate��־��ʾ�������Ѿ����� */
		set_buffer_uptodate(bh);
	} else {
		if (printk_ratelimit()) {/* ��ӡ��ʾ��Ϣ */
			buffer_io_error(bh);
			printk(KERN_WARNING "lost page write due to "
					"I/O error on %s\n",
			       bdevname(bh->b_bdev, b));
		}
		/* ���ô����־�����uptodate��־ */
		set_bit(AS_EIO, &page->mapping->flags);
		clear_buffer_uptodate(bh);
		SetPageError(page);
	}

	spin_lock_irqsave(&page_uptodate_lock, flags);
	/* ����˱�־����ʾд�Ѿ���� */
	clear_buffer_async_write(bh);
	unlock_buffer(bh);
	tmp = bh->b_this_page;
	/* ����������,����������־ */
	while (tmp != bh) {
		if (buffer_async_write(tmp)) {/* ���ĳ���������黹û��д��,���ʾҳ��δ��ȫ��� */
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
		tmp = tmp->b_this_page;
	}
	spin_unlock_irqrestore(&page_uptodate_lock, flags);
	/* ҳ���Ѿ�ȫ����д,����ҳ��ı�־ */
	end_page_writeback(page);
	return;

still_busy:
	spin_unlock_irqrestore(&page_uptodate_lock, flags);
	return;
}

/*
 * If a page's buffers are under async readin (end_buffer_async_read
 * completion) then there is a possibility that another thread of
 * control could lock one of the buffers after it has completed
 * but while some of the other buffers have not completed.  This
 * locked buffer would confuse end_buffer_async_read() into not unlocking
 * the page.  So the absence of BH_Async_Read tells end_buffer_async_read()
 * that this buffer is not under async I/O.
 *
 * The page comes unlocked when it has no locked buffer_async buffers
 * left.
 *
 * PageLocked prevents anyone starting new async I/O reads any of
 * the buffers.
 *
 * PageWriteback is used to prevent simultaneous writeout of the same
 * page.
 *
 * PageLocked prevents anyone from starting writeback of a page which is
 * under read I/O (PageWriteback is only ever set against a locked page).
 */
static void mark_buffer_async_read(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_read;
	set_buffer_async_read(bh);
}

void mark_buffer_async_write(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_write;
	set_buffer_async_write(bh);
}
EXPORT_SYMBOL(mark_buffer_async_write);


/*
 * fs/buffer.c contains helper functions for buffer-backed address space's
 * fsync functions.  A common requirement for buffer-based filesystems is
 * that certain data from the backing blockdev needs to be written out for
 * a successful fsync().  For example, ext2 indirect blocks need to be
 * written back and waited upon before fsync() returns.
 *
 * The functions mark_buffer_inode_dirty(), fsync_inode_buffers(),
 * inode_has_buffers() and invalidate_inode_buffers() are provided for the
 * management of a list of dependent buffers at ->i_mapping->private_list.
 *
 * Locking is a little subtle: try_to_free_buffers() will remove buffers
 * from their controlling inode's queue when they are being freed.  But
 * try_to_free_buffers() will be operating against the *blockdev* mapping
 * at the time, not against the S_ISREG file which depends on those buffers.
 * So the locking for private_list is via the private_lock in the address_space
 * which backs the buffers.  Which is different from the address_space 
 * against which the buffers are listed.  So for a particular address_space,
 * mapping->private_lock does *not* protect mapping->private_list!  In fact,
 * mapping->private_list will always be protected by the backing blockdev's
 * ->private_lock.
 *
 * Which introduces a requirement: all buffers on an address_space's
 * ->private_list must be from the same address_space: the blockdev's.
 *
 * address_spaces which do not place buffers at ->private_list via these
 * utility functions are free to use private_lock and private_list for
 * whatever they want.  The only requirement is that list_empty(private_list)
 * be true at clear_inode() time.
 *
 * FIXME: clear_inode should not call invalidate_inode_buffers().  The
 * filesystems should do that.  invalidate_inode_buffers() should just go
 * BUG_ON(!list_empty).
 *
 * FIXME: mark_buffer_dirty_inode() is a data-plane operation.  It should
 * take an address_space, not an inode.  And it should be called
 * mark_buffer_dirty_fsync() to clearly define why those buffers are being
 * queued up.
 *
 * FIXME: mark_buffer_dirty_inode() doesn't need to add the buffer to the
 * list if it is already on a list.  Because if the buffer is on a list,
 * it *must* already be on the right one.  If not, the filesystem is being
 * silly.  This will save a ton of locking.  But first we have to ensure
 * that buffers are taken *off* the old inode's list when they are freed
 * (presumably in truncate).  That requires careful auditing of all
 * filesystems (do it inside bforget()).  It could also be done by bringing
 * b_inode back.
 */

/*
 * The buffer's backing address_space's private_lock must be held
 */
static inline void __remove_assoc_queue(struct buffer_head *bh)
{
	list_del_init(&bh->b_assoc_buffers);
}

int inode_has_buffers(struct inode *inode)
{
	return !list_empty(&inode->i_data.private_list);
}

/*
 * osync is designed to support O_SYNC io.  It waits synchronously for
 * all already-submitted IO to complete, but does not queue any new
 * writes to the disk.
 *
 * To do O_SYNC writes, just queue the buffer writes with ll_rw_block as
 * you dirty the buffers, and then use osync_inode_buffers to wait for
 * completion.  Any other dirty buffers which are not yet queued for
 * write will not be flushed to disk by the osync.
 */
static int osync_buffers_list(spinlock_t *lock, struct list_head *list)
{
	struct buffer_head *bh;
	struct list_head *p;
	int err = 0;

	spin_lock(lock);
repeat:
	list_for_each_prev(p, list) {
		bh = BH_ENTRY(p);
		if (buffer_locked(bh)) {
			get_bh(bh);
			spin_unlock(lock);
			wait_on_buffer(bh);
			if (!buffer_uptodate(bh))
				err = -EIO;
			brelse(bh);
			spin_lock(lock);
			goto repeat;
		}
	}
	spin_unlock(lock);
	return err;
}

/**
 * sync_mapping_buffers - write out and wait upon a mapping's "associated"
 *                        buffers
 * @buffer_mapping - the mapping which backs the buffers' data
 * @mapping - the mapping which wants those buffers written
 *
 * Starts I/O against the buffers at mapping->private_list, and waits upon
 * that I/O.
 *
 * Basically, this is a convenience function for fsync().  @buffer_mapping is
 * the blockdev which "owns" the buffers and @mapping is a file or directory
 * which needs those buffers to be written for a successful fsync().
 */
/* ��������ͬ�������̣����ȴ������ */
int sync_mapping_buffers(struct address_space *mapping)
{
	/* ��ú��ļ�inode��ַ�ռ�������ĵ�ַ�ռ䣬�����豸inode�ĵ�ַ�ռ� */
	struct address_space *buffer_mapping = mapping->assoc_mapping;

	/* ȷ�����豸��ַ�ռ䲻Ϊ�գ�������private_list�ǿ��豸��ͬ��Ԫ���ݲ�Ϊ��(��ʾ��Ԫ������Ҫͬ��) */
	if (buffer_mapping == NULL || list_empty(&mapping->private_list))
		return 0;

	/* �����豸��Ԫ����ͬ�������� */
	return fsync_buffers_list(&buffer_mapping->private_lock,
					&mapping->private_list);
}
EXPORT_SYMBOL(sync_mapping_buffers);

/*
 * Called when we've recently written block `bblock', and it is known that
 * `bblock' was for a buffer_boundary() buffer.  This means that the block at
 * `bblock + 1' is probably a dirty indirect block.  Hunt it down and, if it's
 * dirty, schedule it for IO.  So that indirects merge nicely with their data.
 */
void write_boundary_block(struct block_device *bdev,
			sector_t bblock, unsigned blocksize)
{
	struct buffer_head *bh = __find_get_block(bdev, bblock + 1, blocksize);
	if (bh) {
		if (buffer_dirty(bh))
			ll_rw_block(WRITE, 1, &bh);
		put_bh(bh);
	}
}

void mark_buffer_dirty_inode(struct buffer_head *bh, struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct address_space *buffer_mapping = bh->b_page->mapping;

	mark_buffer_dirty(bh);
	if (!mapping->assoc_mapping) {
		mapping->assoc_mapping = buffer_mapping;
	} else {
		if (mapping->assoc_mapping != buffer_mapping)
			BUG();
	}
	if (list_empty(&bh->b_assoc_buffers)) {
		spin_lock(&buffer_mapping->private_lock);
		list_move_tail(&bh->b_assoc_buffers,
				&mapping->private_list);
		spin_unlock(&buffer_mapping->private_lock);
	}
}
EXPORT_SYMBOL(mark_buffer_dirty_inode);

/*
 * Add a page to the dirty page list.
 *
 * It is a sad fact of life that this function is called from several places
 * deeply under spinlocking.  It may not sleep.
 *
 * If the page has buffers, the uptodate buffers are set dirty, to preserve
 * dirty-state coherency between the page and the buffers.  It the page does
 * not have buffers then when they are later attached they will all be set
 * dirty.
 *
 * The buffers are dirtied before the page is dirtied.  There's a small race
 * window in which a writepage caller may see the page cleanness but not the
 * buffer dirtiness.  That's fine.  If this code were to set the page dirty
 * before the buffers, a concurrent writepage caller could clear the page dirty
 * bit, see a bunch of clean buffers and we'd end up with dirty buffers/clean
 * page on the dirty page list.
 *
 * We use private_lock to lock against try_to_free_buffers while using the
 * page's buffer list.  Also use this to protect against clean buffers being
 * added to the page after it was set dirty.
 *
 * FIXME: may need to call ->reservepage here as well.  That's rather up to the
 * address_space though.
 */
int __set_page_dirty_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;

	spin_lock(&mapping->private_lock);
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		do {
			set_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	spin_unlock(&mapping->private_lock);

	if (!TestSetPageDirty(page)) {
		spin_lock_irq(&mapping->tree_lock);
		if (page->mapping) {	/* Race with truncate? */
			if (!mapping->backing_dev_info->memory_backed)
				inc_page_state(nr_dirty);
			radix_tree_tag_set(&mapping->page_tree,
						page_index(page),
						PAGECACHE_TAG_DIRTY);
		}
		spin_unlock_irq(&mapping->tree_lock);
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);
	}
	
	return 0;
}
EXPORT_SYMBOL(__set_page_dirty_buffers);

/*
 * Write out and wait upon a list of buffers.
 *
 * We have conflicting pressures: we want to make sure that all
 * initially dirty buffers get waited on, but that any subsequently
 * dirtied buffers don't.  After all, we don't want fsync to last
 * forever if somebody is actively writing to the file.
 *
 * Do this in two main stages: first we copy dirty buffers to a
 * temporary inode list, queueing the writes as we go.  Then we clean
 * up, waiting for those writes to complete.
 * 
 * During this second stage, any subsequent updates to the file may end
 * up refiling the buffer on the original inode's dirty list again, so
 * there is a chance we will end up with a buffer queued for write but
 * not yet completed on that list.  So, as a final cleanup we go through
 * the osync code to catch these locked, dirty buffers without requeuing
 * any newly dirty buffers for write.
 */
static int fsync_buffers_list(spinlock_t *lock, struct list_head *list)
{
	struct buffer_head *bh;
	struct list_head tmp;
	int err = 0, err2;

	INIT_LIST_HEAD(&tmp);

	spin_lock(lock);
	while (!list_empty(list)) {
		bh = BH_ENTRY(list->next);
		list_del_init(&bh->b_assoc_buffers);
		if (buffer_dirty(bh) || buffer_locked(bh)) {
			list_add(&bh->b_assoc_buffers, &tmp);
			if (buffer_dirty(bh)) {
				get_bh(bh);
				spin_unlock(lock);
				/*
				 * Ensure any pending I/O completes so that
				 * ll_rw_block() actually writes the current
				 * contents - it is a noop if I/O is still in
				 * flight on potentially older contents.
				 */
				wait_on_buffer(bh);
				ll_rw_block(WRITE, 1, &bh);
				brelse(bh);
				spin_lock(lock);
			}
		}
	}

	while (!list_empty(&tmp)) {
		bh = BH_ENTRY(tmp.prev);
		__remove_assoc_queue(bh);
		get_bh(bh);
		spin_unlock(lock);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh))
			err = -EIO;
		brelse(bh);
		spin_lock(lock);
	}
	
	spin_unlock(lock);
	err2 = osync_buffers_list(lock, list);
	if (err)
		return err;
	else
		return err2;
}

/*
 * Invalidate any and all dirty buffers on a given inode.  We are
 * probably unmounting the fs, but that doesn't mean we have already
 * done a sync().  Just drop the buffers from the inode list.
 *
 * NOTE: we take the inode's blockdev's mapping's private_lock.  Which
 * assumes that all the buffers are against the blockdev.  Not true
 * for reiserfs.
 */
void invalidate_inode_buffers(struct inode *inode)
{
	if (inode_has_buffers(inode)) {
		struct address_space *mapping = &inode->i_data;
		struct list_head *list = &mapping->private_list;
		struct address_space *buffer_mapping = mapping->assoc_mapping;

		spin_lock(&buffer_mapping->private_lock);
		while (!list_empty(list))
			__remove_assoc_queue(BH_ENTRY(list->next));
		spin_unlock(&buffer_mapping->private_lock);
	}
}

/*
 * Remove any clean buffers from the inode's buffer list.  This is called
 * when we're trying to free the inode itself.  Those buffers can pin it.
 *
 * Returns true if all buffers were removed.
 */
int remove_inode_buffers(struct inode *inode)
{
	int ret = 1;

	if (inode_has_buffers(inode)) {
		struct address_space *mapping = &inode->i_data;
		struct list_head *list = &mapping->private_list;
		struct address_space *buffer_mapping = mapping->assoc_mapping;

		spin_lock(&buffer_mapping->private_lock);
		while (!list_empty(list)) {
			struct buffer_head *bh = BH_ENTRY(list->next);
			if (buffer_dirty(bh)) {
				ret = 0;
				break;
			}
			__remove_assoc_queue(bh);
		}
		spin_unlock(&buffer_mapping->private_lock);
	}
	return ret;
}

/*
 * Create the appropriate buffers when given a page for data area and
 * the size of each buffer.. Use the bh->b_this_page linked list to
 * follow the buffers created.  Return NULL if unable to create more
 * buffers.
 *
 * The retry flag is used to differentiate async IO (paging, swapping)
 * which may not fail from ordinary buffer allocations.
 */
/**
 * ����ҳ��������Ŀ��С���仺�����ײ����������ǲ�����b_this_page�ֶ�ʵ�ֵĵ���ѭ������
 * ���⣬������ҳ�������ĵ�ַ��ʼ���������ײ���b_page�ֶΡ��ÿ黺������ҳ�ڵ����Ե�ַ��ƫ������ʼ��b_data�ֶ�
 */
struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		int retry)
{
	struct buffer_head *bh, *head;
	long offset;

try_again:
	head = NULL;
	offset = PAGE_SIZE;
    /*
     * ע��: 
     * 1. �ǴӺ���ǰ����ģ�Ҳ�����ȷ�����������һ��Ԫ�أ����headָ�����ײ�
     * 2. ���η����ʱ�򣬾ͽ����е�bh��b_data������size���ú��ˣ�������init_page_buffersʱ��ֻҪ������ص�dev,block�Ϳ�����
     *    ��ʵ���൱�ڸ���size�������bh���͵ȴ��Ź�����Ŀ���豸���ѡ�
     */
	while ((offset -= size) >= 0) { 
		bh = alloc_buffer_head(GFP_NOFS); /*��*/
		if (!bh)
			goto no_grow;

		bh->b_bdev = NULL;
		bh->b_this_page = head; /*��*/
		bh->b_blocknr = -1;
		head = bh;  /*��*/

		bh->b_state = 0;
		atomic_set(&bh->b_count, 0);
		bh->b_size = size;   /*��*/

		/* Link the buffer to its page */
        /*�趨b_data�ȹؼ��ֶ�*/
		set_bh_page(bh, page, offset); /*��*/

		bh->b_end_io = NULL;
	}
	return head;
/*
 * In case anything failed, we just free everything we got.
 */
no_grow:
	if (head) {
		do {
			bh = head;
			head = head->b_this_page;
			free_buffer_head(bh);
		} while (head);
	}

	/*
	 * Return failure for non-async IO requests.  Async IO requests
	 * are not allowed to fail, so we have to wait until buffer heads
	 * become available.  But we don't want tasks sleeping with 
	 * partially complete buffers, so all were released above.
	 */
	if (!retry)
		return NULL;

	/* We're _really_ low on memory. Now we just
	 * wait for old buffer heads to become free due to
	 * finishing IO.  Since this is an async request and
	 * the reserve list is empty, we're sure there are 
	 * async buffer heads in use.
	 */
	free_more_memory();
	goto try_again;
}
EXPORT_SYMBOL_GPL(alloc_page_buffers);

static inline void
link_dev_buffers(struct page *page, struct buffer_head *head)
{
	struct buffer_head *bh, *tail;

	bh = head;
	do {
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;
	attach_page_buffers(page, head);
}

/*
 * Initialise the state of a blockdev page's buffers.
 */ 
static void
init_page_buffers(struct page *page, struct block_device *bdev,
			sector_t block, int size)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh = head;
	int uptodate = PageUptodate(page);

	do {
        /*
         * ���bh��û��ӳ�䵽���̣���ʼ��buffer, ������bh�Ѿ�ӳ�䵽����
         * �ҵ���һ����û��ӳ���bh����ӳ�����
         */
		if (!buffer_mapped(bh)) {
			init_buffer(bh, NULL, NULL);
			bh->b_bdev = bdev; /*��*/
			bh->b_blocknr = block; /*��*/
			if (uptodate)
				set_buffer_uptodate(bh);
			set_buffer_mapped(bh);
		}
		block++;
		bh = bh->b_this_page;
	} while (bh != head);
}

/*
 * Create the page-cache page that contains the requested block.
 *
 * This is user purely for blockdev mappings.
 */
/**
 * �����µĿ��豸������ҳ��
 */
static struct page *
grow_dev_page(struct block_device *bdev, sector_t block,
		pgoff_t index, int size)
{
	struct inode *inode = bdev->bd_inode;
	struct page *page;
	struct buffer_head *bh;

	/**
	 * ����find_or_create_page�����ݵĲ����ǿ��豸��address_space����ҳƫ��index�Լ�GFP_NOFS��־��
	 * �ú�����ҳ���ٻ�����������Ҫ��ҳ�������Ҫ���Ͱ���ҳ����ҳ���ٻ��档
	 */
	page = find_or_create_page(inode->i_mapping, index, GFP_NOFS); /*��*/
	if (!page)
		return NULL;

	if (!PageLocked(page))
		BUG();

	/**
	 * ҳ�Ѿ���ҳ���ٻ����С��������PG_private��־��
	 */
	if (page_has_buffers(page)) {
		/**
		 * ҳ�Ѿ��ǻ�����ҳ����ҳ��������private�ֶλ�õ�һ���������ײ��ĵ�ַbh��
		 */
		bh = page_buffers(page);
		/**
		 * ���ҳ�п�Ĵ�С, �����С��ȣ�˵���ҵ�����Ч�Ļ�����ҳ��
		 * ����init_page_buffers ��ʼ�����ӵ�ҳ�Ļ������׶����ֶ�
		 */
		if (bh->b_size == size) {
			init_page_buffers(page, bdev, block, size); /*��*/
			return page;
		}
		/**
		 * ҳ�п�Ĵ�С�д��󣬾͵���try_to_free_buffers�ͷŻ�����ҳ����һ���������ײ���
		 */
		if (!try_to_free_buffers(page)) /*��*/
			goto failed;
	}

	/*
	 * Allocate some buffers for this page
	 */
	/**
	 * ҳ�����ǻ�����ҳ������alloc_page_buffers����ҳ������Ŀ��С���仺�����ײ���
	 * �������ǲ�����b_this_page�ֶ�ʵ�ֵĵ���ѭ�������С�
	 * ���⣬������ҳ�������ĵ�ַ��ʼ���������ײ���b_page�ֶΣ��ÿ黺������ҳ�ڵĴ�����ַ����ƫ������ʼ��b_data�ֶΡ�
	 */
	bh = alloc_page_buffers(page, size, 0); /*��*/
	if (!bh)
		goto failed;

	/*
	 * Link the page to the buffers and initialise them.  Take the
	 * lock to be atomic wrt __find_get_block(), which does not
	 * run under the page lock.
	 */
	/**
	 * ���ֶ�private�д�ŵ�һ���������ײ��ĵ�ַ����PG_private�ֶ���λ��������ҳ��ʹ�ü�������
	 */ 
	spin_lock(&inode->i_mapping->private_lock); /*��*/
	link_dev_buffers(page, bh); /*��*/
	/**
	 * init_page_buffers������ʼ�����ӵ�ҳ�Ļ������ײ���b_bdev��b_blocknr��b_bstate�ֶΡ�
	 * ��Ϊ���еĿ��ڴ����϶������ڵģ�����߼�����������ġ�
	 */
	init_page_buffers(page, bdev, block, size);
	spin_unlock(&inode->i_mapping->private_lock);
	return page;

failed:
	BUG();
	unlock_page(page);
	page_cache_release(page);
	return NULL;
}

/*
 * Create buffers for the specified block device block's page.  If
 * that page was dirty, the buffers are set dirty also.
 *
 * Except that's a bug.  Attaching dirty buffers to a dirty
 * blockdev's page can result in filesystem corruption, because
 * some of those buffers may be aliases of filesystem data.
 * grow_dev_page() will go BUG() if this happens.
 */
/**
 * �ѿ��豸������ҳ��ӵ�ҳ���ٻ����С�
 * bdev:		���豸������
 * block:		�߼����
 * size:		���С
 */
static inline int
grow_buffers(struct block_device *bdev, sector_t block, int size)
{
	struct page *page;
	pgoff_t index;
	int sizebits;

	/**
	 * ��������ҳ���������Ŀ��豸�е�ƫ����index
	 */
	sizebits = -1;
	do {
		sizebits++;
	} while ((size << sizebits) < PAGE_SIZE);

    /*
     * ������λ���㷨������μ� P614 �ĵڶ�������
     */
	index = block >> sizebits;
	block = index << sizebits; /*��Ϊ���еĿ�(����� P610)�ڴ����϶������ڵģ�����߼�����������ģ����Һ����׵ó�*/

	/* Create a page with the proper size buffers.. */
	/**
	 * ����grow_dev_page�����µĿ��豸������ҳ��
	 */
	page = grow_dev_page(bdev, block, index, size);
	if (!page)
		return 0;
	/**
	 * Ϊҳ��������Ϊ��grow_dev_page��Ϊpage��������
	 */
	unlock_page(page);
	/**
	 * �ݼ�ҳ��ʹ�ü�����(����find_or_create_page�������˼�����)
	 */
	page_cache_release(page);
	return 1;
}

/**
 * Ϊ�����ҳ�����һ���µĻ�������
 */
struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block, int size)
{
	/* Size must be multiple of hard sectorsize */
	if (unlikely(size & (bdev_hardsect_size(bdev)-1) ||
			(size < 512 || size > PAGE_SIZE))) {
		printk(KERN_ERR "getblk(): invalid block size %d requested\n",
					size);
		printk(KERN_ERR "hardsect size: %d\n",
					bdev_hardsect_size(bdev));

		dump_stack();
		return NULL;
	}

	for (;;) {
		struct buffer_head * bh;

		/**
		 * ȷ���������Ƿ��Ѿ���ҳ���ٻ����С�
		 */
		bh = __find_get_block(bdev, block, size);
		if (bh)
			return bh;

		/**
		 * ����ҳ���ٻ����У������grow_buffersΪ�������ҳ����һ���µĻ�����ҳ��
		 */
		if (!grow_buffers(bdev, block, size))
			free_more_memory();/* ����ҳʧ�ܣ�����ͼͨ�����ú���free_more_memory����һ�����ڴ� */
	}
}

/*
 * The relationship between dirty buffers and dirty pages:
 *
 * Whenever a page has any dirty buffers, the page's dirty bit is set, and
 * the page is tagged dirty in its radix tree.
 *
 * At all times, the dirtiness of the buffers represents the dirtiness of
 * subsections of the page.  If the page has buffers, the page dirty bit is
 * merely a hint about the true dirty state.
 *
 * When a page is set dirty in its entirety, all its buffers are marked dirty
 * (if the page has buffers).
 *
 * When a buffer is marked dirty, its page is dirtied, but the page's other
 * buffers are not.
 *
 * Also.  When blockdev buffers are explicitly read with bread(), they
 * individually become uptodate.  But their backing page remains not
 * uptodate - even if all of its buffers are uptodate.  A subsequent
 * block_read_full_page() against that page will discover all the uptodate
 * buffers, will set the page uptodate and will perform no I/O.
 */

/**
 * mark_buffer_dirty - mark a buffer_head as needing writeout
 *
 * mark_buffer_dirty() will set the dirty bit against the buffer, then set its
 * backing page dirty, then tag the page as dirty in its address_space's radix
 * tree and then attach the address_space's inode to its superblock's dirty
 * inode list.
 *
 * mark_buffer_dirty() is atomic.  It takes bh->b_page->mapping->private_lock,
 * mapping->tree_lock and the global inode_lock.
 */
void fastcall mark_buffer_dirty(struct buffer_head *bh)
{
	if (!buffer_dirty(bh) && !test_set_buffer_dirty(bh))
		__set_page_dirty_nobuffers(bh->b_page);
}

/*
 * Decrement a buffer_head's reference count.  If all buffers against a page
 * have zero reference count, are clean and unlocked, and if the page is clean
 * and unlocked then try_to_free_buffers() may strip the buffers from the page
 * in preparation for freeing it (sometimes, rarely, buffers are removed from
 * a page but it ends up not being freed, and buffers may later be reattached).
 */
/**
 * ���ں˿���·��ֹͣ���ʿ黺����ʱ����Ҫ����brelse�ݼ���Ӧ�����ü�������
 * ��ע������__bforget֮��Ĳ��
 */
void __brelse(struct buffer_head * buf)
{
	if (atomic_read(&buf->b_count)) {
		put_bh(buf); 
		return;
	}
	printk(KERN_ERR "VFS: brelse: Trying to free free buffer\n");
	WARN_ON(1);
}

/*
 * bforget() is like brelse(), except it discards any
 * potentially dirty data.
 */
/**
 * ���ں�ֹͣ���ʿ黺����ʱ��Ӧ�õ���__brelse����__bforget�ݼ���Ӧ�����ü�������
 * ʵ���ϣ�__bforget���᣺�Ӽ�ӿ������������ײ���b_assoc_buufers�ֶΣ���ɾ���顣
 * ���Ѹû��������Ϊ�ɾ��ġ����ǿ���ں˺��ԶԻ������������κ��޸ġ�
 * ���ǣ�ʵ���ϻ�������Ȼ���뱻д�ش��̡�
 */
void __bforget(struct buffer_head *bh)
{
	clear_buffer_dirty(bh);
	if (!list_empty(&bh->b_assoc_buffers)) {
		struct address_space *buffer_mapping = bh->b_page->mapping;

		spin_lock(&buffer_mapping->private_lock);
		list_del_init(&bh->b_assoc_buffers); /*��*/
		spin_unlock(&buffer_mapping->private_lock);
	}
	__brelse(bh); /*��*/
}
/**
 * �ӿ��豸�ж�ȡ�������ײ�
 */
static struct buffer_head *__bread_slow(struct buffer_head *bh)
{
	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return bh;
	} else {
		/**
		 * �������ӻ����������ü�����
		 */
		get_bh(bh);
		/**
		 * ��end_buffer_read_sync����b_end_io�������豸��ȡ�����ݺ󣬻�ص��˺�����
		 */
		bh->b_end_io = end_buffer_read_sync;
		/**
		 * ����submit_bh�ѻ������ײ����͵�ͨ�ÿ�㡣
		 */
		submit_bh(READ, bh);
		/**
		 * ����wait_on_buffer �ѵ�ǰ������뵽�ȴ����У�ֱ��I/O������ɡ�
		 */
		wait_on_buffer(bh);
		if (buffer_uptodate(bh))
			return bh;
	}
	brelse(bh);
	return NULL;
}

/*
 * Per-cpu buffer LRU implementation.  To reduce the cost of __find_get_block().
 * The bhs[] array is sorted - newest buffer is at bhs[0].  Buffers have their
 * refcount elevated by one when they're in an LRU.  A buffer can only appear
 * once in a particular CPU's LRU.  A single buffer can be present in multiple
 * CPU's LRUs at the same time.
 *
 * This is a transparent caching front-end to sb_bread(), sb_getblk() and
 * sb_find_get_block().
 *
 * The LRUs themselves only need locking against invalidate_bh_lrus.  We use
 * a local interrupt disable for that.
 */

#define BH_LRU_SIZE	8

struct bh_lru {
	struct buffer_head *bhs[BH_LRU_SIZE];
};

/**
 * ��ҳ���ٻ�����������ʱ��Ϊ��������ܣ��ں�ά��һ��С�Ĵ��̸��ٻ�������bh_lrus��ÿCPU��������
 * ����ν���������ʹ�ã�LRU������ٻ��档
 * ÿ�����̸��ٻ�����8��ָ�룬ָ��ָ��CPU������ʹ��Ļ������ײ���
 * ��ÿ��CPU�����ݽ�������ʹָ�����ʹ�ù����Ǹ��������ײ���ָ������Ϊ0��
 * ��ͬ�Ļ������ײ����ܳ����ڼ���CPU�����С�
 * ��LRU ����ٻ�����ÿ����һ�λ������ײ����û������ײ���ʹ�ü��� b_count �ͼ�1
 */
static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

#ifdef CONFIG_SMP
#define bh_lru_lock()	local_irq_disable()
#define bh_lru_unlock()	local_irq_enable()
#else
#define bh_lru_lock()	preempt_disable()
#define bh_lru_unlock()	preempt_enable()
#endif

static inline void check_irqs_on(void)
{
#ifdef irqs_disabled
	BUG_ON(irqs_disabled());
#endif
}

/*
 * The LRU management algorithm is dopey-but-simple.  Sorry.
 */
static void bh_lru_install(struct buffer_head *bh)
{
	struct buffer_head *evictee = NULL;
	struct bh_lru *lru;

	check_irqs_on();
	bh_lru_lock();
	lru = &__get_cpu_var(bh_lrus);
	if (lru->bhs[0] != bh) {
		struct buffer_head *bhs[BH_LRU_SIZE];
		int in;
		int out = 0;

		get_bh(bh);
        /*�������ĵ�һ��Ԫ�ط�bh*/
		bhs[out++] = bh;
        /*
         * ԭ���������Ԫ��˳�����������������λ����
         * ע������ԭ��bh�Ѿ��ڵ�λ�ã�
         * ���ԭ��������һ��Ԫ���Ѿ��Ų����ˣ���ô��¼��evictee��
         */
		for (in = 0; in < BH_LRU_SIZE; in++) {
			struct buffer_head *bh2 = lru->bhs[in];

			if (bh2 == bh) {
				__brelse(bh2);
			} else {
				if (out >= BH_LRU_SIZE) {
					BUG_ON(evictee != NULL);
					evictee = bh2;
				} else {
					bhs[out++] = bh2;
				}
			}
		}
        /*����������飬ʣ�µ���д0*/
		while (out < BH_LRU_SIZE)
			bhs[out++] = NULL;
        /*���µ�bhsд����ٻ���lru��*/
		memcpy(lru->bhs, bhs, sizeof(bhs));
	}
	bh_lru_unlock();

    /*����Ѿ��Ų��µ�ԭ���ٻ���Ԫ�أ����ͷ������ü���*/
	if (evictee)
		__brelse(evictee);
}

/*
 * Look up the bh in this cpu's LRU.  If it's there, move it to the head.
 */
static inline struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, int size)
{
	struct buffer_head *ret = NULL;
	struct bh_lru *lru;
	int i;

	check_irqs_on();
	bh_lru_lock();
    /*ȡ�ñ�CPU��LRU*/
	lru = &__get_cpu_var(bh_lrus);
    /*����LRU�����е�����Ԫ��*/
	for (i = 0; i < BH_LRU_SIZE; i++) {
		struct buffer_head *bh = lru->bhs[i];

        /*����ҵ���[i], ��ô��[0,i-1]��˳�����һ��λ�ã�Ȼ��i����0��λ�ã�������bh*/
		if (bh && bh->b_bdev == bdev &&
				bh->b_blocknr == block && bh->b_size == size) {
			if (i) {
				while (i) {
					lru->bhs[i] = lru->bhs[i - 1];
					i--;
				}
				lru->bhs[0] = bh;
			}
			get_bh(bh);
			ret = bh;
			break;
		}
	}
	bh_lru_unlock();
	return ret;
}

/*
 * Perform a pagecache lookup for the matching buffer.  If it's there, refresh
 * it in the LRU and mark it as accessed.  If it is not present then return
 * NULL
 */
/**
 * ����ҳ���ٻ����еĿ黺������Ӧ�Ļ������ײ��ĵ�ַ����������ڣ��ͷ���NULL��
 * bdev:	�豸��������
 * block:	Ҫ�����Ŀ�š�
 * size:	���С��
 */
struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, int size)
{
	/**
	 * ���CPU��LRU����ٻ����������Ƿ���һ���������ײ���
	 * ����������ײ���LRU����ٻ����У���ˢ�������е�Ԫ�أ��Ա���ָ��ָ�ڵ�һ��λ�ã���������b_count�ֶΡ�
	 */
	struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

	if (bh == NULL) {
		/**
		 * �������ײ�����LRU����ٻ����У������__find_get_block_slow�ڸ��ٻ�����������
		 */
		bh = __find_get_block_slow(bdev, block, size);
		if (bh)
			/*
			 * ��LRU  ����ٻ����е�����Ԫ�������ƶ�һ��λ�ã�
			 * ����ִ��������Ŀ�Ļ������ײ��嵽��һ��λ�á�
			 * ���һ���������ײ��Ѿ�����LRU ����ٻ����У��͵ݼ��������ü���b_count
			 */
			bh_lru_install(bh);
	}
	/**
	 * ����б�Ҫ���͵���mark_page_accessed�ѻ�����ҳ�����ʵ���LRU�����С�
	 */
	if (bh)
		touch_buffer(bh);
	return bh;
}
EXPORT_SYMBOL(__find_get_block);

/*
 * __getblk will locate (and, if necessary, create) the buffer_head
 * which corresponds to the passed block_device, block and size. The
 * returned buffer has its reference count incremented.
 *
 * __getblk() cannot fail - it just keeps trying.  If you pass it an
 * illegal block number, __getblk() will happily return a buffer_head
 * which represents the non-existent block.  Very weird.
 *
 * __getblk() will lock up the machine if grow_dev_page's try_to_free_buffers()
 * attempt is failing.  FIXME, perhaps?
 */
/**
 * ȷ������ҳ���ٻ����е�λ�á�
 * ���Զ�������ü��������ӣ���˸߲㺯�����������ӿ黺���������ü�������
 *
 * ����ҳ���ٻ����еĿ黺������Ӧ�Ļ������ײ��ĵ�ַ����������ڣ��ͷ�����豸������ҳ�����ػ������ײ�ָ�롣
 * __getblk���صĿ黺�������ش�����Ч���� -- �������ײ���BH_Uptodate��־��������
 * bdev:	�豸��������
 * block:	Ҫ�����Ŀ�š�
 * size:	���С��
 */
 struct buffer_head *
__getblk(struct block_device *bdev, sector_t block, int size)
{
	/**
	 * __find_get_block�����Ƿ��Ѿ���ҳ���ٻ����С�����ҵ����ͷ��ػ������ײ���ַ��
	 */
	struct buffer_head *bh = __find_get_block(bdev, block, size);

	might_sleep();
	/**
	 * û���ڸ��ٻ����ײ��ҵ��������ҳ��
	 * �����grow_buffersΪ�������ҳ����һ���µĻ�����ҳ��
	 */
	if (bh == NULL)
		bh = __getblk_slow(bdev, block, size);
	return bh;
}
EXPORT_SYMBOL(__getblk);

/*
 * Do async read-ahead on a buffer..
 */
void __breadahead(struct block_device *bdev, sector_t block, int size)
{
	struct buffer_head *bh = __getblk(bdev, block, size);
	ll_rw_block(READA, 1, &bh);
	brelse(bh);
}
EXPORT_SYMBOL(__breadahead);

/**
 *  __bread() - reads a specified block and returns the bh
 *  @block: number of block
 *  @size: size (in bytes) to read
 * 
 *  Reads a specified block, and returns buffer head that contains it.
 *  It returns NULL if the block was unreadable.
 */
/**
 * �ú�����__getblk���ƣ�������__getblk�෴���ǣ������Ҫ�Ļ������ͻ��ڷ��ػ������ײ�֮ǰ�Ӵ����ж�ȡ������ݡ�
 */
struct buffer_head *
__bread(struct block_device *bdev, sector_t block, int size)
{
	/**
	 * ����__getblk��ҳ���ٻ����в�����������Ŀ���صĻ�����ҳ�������ָ����Ӧ�Ļ������ײ���ָ�롣
	 */
	struct buffer_head *bh = __getblk(bdev, block, size);

	/**
	 * ���л�û�а�����Ч����(BH_Uptodate��־û�б���λ)
	 */
	if (!buffer_uptodate(bh))
		/**
		 * __bread_slow�����ͨ�ÿ��ĺ�����ȡ���ݵ��ڴ��С�
		 */
		bh = __bread_slow(bh);
	/*
	 * �黺��ͷ�������Ѿ���������Ч���ݣ����ػ�����ͷ����ַ
	 */
	return bh;
}
EXPORT_SYMBOL(__bread);

/*
 * invalidate_bh_lrus() is called rarely - but not only at unmount.
 * This doesn't race because it runs in each cpu either in irq
 * or with preempt disabled.
 */
static void invalidate_bh_lru(void *arg)
{
	struct bh_lru *b = &get_cpu_var(bh_lrus);
	int i;

	for (i = 0; i < BH_LRU_SIZE; i++) {
		brelse(b->bhs[i]);
		b->bhs[i] = NULL;
	}
	put_cpu_var(bh_lrus);
}


static void invalidate_bh_lrus(void)
{
	on_each_cpu(invalidate_bh_lru, NULL, 1, 1);
}

/*
 * ���������˹ؼ���b_data, �Ǹ߶��ڴ�ֱ������ΪVA���߶��ڴ�Ϊoffset
 */
void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset)
{
	bh->b_page = page;
	if (offset >= PAGE_SIZE)
		BUG();
	if (PageHighMem(page))
		/*
		 * This catches illegal uses and preserves the offset:
		 */
		bh->b_data = (char *)(0 + offset); /*��*/
	else
		bh->b_data = page_address(page) + offset; /*��*/
}
EXPORT_SYMBOL(set_bh_page);

/*
 * Called when truncating a buffer on a page completely.
 */
static inline void discard_buffer(struct buffer_head * bh)
{
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	bh->b_bdev = NULL;
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	unlock_buffer(bh);
}

/**
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).  If the release was successful, return `1'.
 * Otherwise return zero.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_WAIT).
 *
 * NOTE: @gfp_mask may go away, and this function may become non-blocking.
 */
/**
 * �ͷŻ�����ҳ��
 * page:	Ҫ�ͷŵ�ҳ��������ַ��
 */
int try_to_release_page(struct page *page, int gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	/**
	 * ������ͼ��ҳд�ش��̣���˲��ܽ�ҳ�ͷš�
	 */ 
	if (PageWriteback(page))
		return 0;

	/**
	 * ��������˿��豸��address_space�����releasepage�������͵�������
	 * �ûص�����ͨ����û�ж���ġ�
	 */
	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	/**
	 * try_to_free_buffers�������μ��ҳ�еĻ������ײ���־��
	 * ע������ֻ�ͷ�buffer_head�����ͷ�ҳ�汾���ɵ������ͷ�ҳ�棬������μ�shrink_list��free_it��ǩ
	 */
	return try_to_free_buffers(page);
}
EXPORT_SYMBOL(try_to_release_page);

/**
 * block_invalidatepage - invalidate part of all of a buffer-backed page
 *
 * @page: the page which is affected
 * @offset: the index of the truncation point
 *
 * block_invalidatepage() is called when all or part of the page has become
 * invalidatedby a truncate operation.
 *
 * block_invalidatepage() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
int block_invalidatepage(struct page *page, unsigned long offset)
{
	struct buffer_head *head, *bh, *next;
	unsigned int curr_off = 0;
	int ret = 1;

	BUG_ON(!PageLocked(page));
	if (!page_has_buffers(page))
		goto out;

	head = page_buffers(page);
	bh = head;
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		/*
		 * is this block fully invalidated?
		 */
		if (offset <= curr_off)
			discard_buffer(bh);
		curr_off = next_off;
		bh = next;
	} while (bh != head);

	/*
	 * We release buffers only if the entire page is being invalidated.
	 * The get_block cached value has been unconditionally invalidated,
	 * so real IO is not possible anymore.
	 */
	if (offset == 0)
		ret = try_to_release_page(page, 0);
out:
	return ret;
}
EXPORT_SYMBOL(block_invalidatepage);

/*
 * We attach and possibly dirty the buffers atomically wrt
 * __set_page_dirty_buffers() via private_lock.  try_to_free_buffers
 * is already excluded via the page lock.
 */
/**
 * Ϊҳ�����黺�������仺�����ײ���
 */
void create_empty_buffers(struct page *page,
			unsigned long blocksize, unsigned long b_state)
{
	struct buffer_head *bh, *head, *tail;

	head = alloc_page_buffers(page, blocksize, 1); /*��*/
	bh = head;
	do {
		bh->b_state |= b_state;
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;

	spin_lock(&page->mapping->private_lock);
	if (PageUptodate(page) || PageDirty(page)) {
		bh = head;
		do {
			if (PageDirty(page))
				set_buffer_dirty(bh);
			if (PageUptodate(page))
				set_buffer_uptodate(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	attach_page_buffers(page, head); /*��*/
	spin_unlock(&page->mapping->private_lock);
}
EXPORT_SYMBOL(create_empty_buffers);

/*
 * We are taking a block for data and we don't want any output from any
 * buffer-cache aliases starting from return from that function and
 * until the moment when something will explicitly mark the buffer
 * dirty (hopefully that will not happen until we will free that block ;-)
 * We don't even need to mark it not-uptodate - nobody can expect
 * anything from a newly allocated buffer anyway. We used to used
 * unmap_buffer() for such invalidation, but that was wrong. We definitely
 * don't want to mark the alias unmapped, for example - it would confuse
 * anyone who might pick it with bread() afterwards...
 *
 * Also..  Note that bforget() doesn't lock the buffer.  So there can
 * be writeout I/O going on against recently-freed buffers.  We don't
 * wait on that I/O in bforget() - it's more efficient to wait on the I/O
 * only if we really need to.  That happens here.
 */
void unmap_underlying_metadata(struct block_device *bdev, sector_t block)
{
	struct buffer_head *old_bh;

	might_sleep();

	old_bh = __find_get_block_slow(bdev, block, 0);
	if (old_bh) {
		clear_buffer_dirty(old_bh);
		wait_on_buffer(old_bh);
		clear_buffer_req(old_bh);
		__brelse(old_bh);
	}
}
EXPORT_SYMBOL(unmap_underlying_metadata);

/*
 * NOTE! All mapped/uptodate combinations are valid:
 *
 *	Mapped	Uptodate	Meaning
 *
 *	No	No		"unknown" - must do get_block()
 *	No	Yes		"hole" - zero-filled
 *	Yes	No		"allocated" - allocated on disk, not read in
 *	Yes	Yes		"valid" - allocated and up-to-date in memory.
 *
 * "Dirty" is valid only with the last case (mapped+uptodate).
 */

/*
 * While block_write_full_page is writing back the dirty buffers under
 * the page lock, whoever dirtied the buffers may decide to clean them
 * again at any time.  We handle that by only looking at the buffer
 * state inside lock_buffer().
 *
 * If block_write_full_page() is called for regular writeback
 * (wbc->sync_mode == WB_SYNC_NONE) then it will redirty a page which has a
 * locked buffer.   This only can happen if someone has written the buffer
 * directly, with submit_bh().  At the address_space level PageWriteback
 * prevents this contention from occurring.
 */
static int __block_write_full_page(struct inode *inode, struct page *page,
			get_block_t *get_block, struct writeback_control *wbc)
{
	int err;
	sector_t block;
	sector_t last_block;
	struct buffer_head *bh, *head;
	int nr_underway = 0;

	BUG_ON(!PageLocked(page));

	/* �����ļ����һ����ı�� */
	last_block = (i_size_read(inode) - 1) >> inode->i_blkbits;
	/**
	 * ��block_read_full_pageһ���������û���ڻ�����ҳ�У��ͷ��仺�����ײ�
	 */
	if (!page_has_buffers(page)) {
		create_empty_buffers(page, 1 << inode->i_blkbits,
					(1 << BH_Dirty)|(1 << BH_Uptodate)); /*��*/
	}

	/*
	 * Be very careful.  We have no exclusion from __set_page_dirty_buffers
	 * here, and the (potentially unmapped) buffers may become dirty at
	 * any time.  If a buffer becomes dirty here after we've inspected it
	 * then we just miss that fact, and the page stays dirty.
	 *
	 * Buffers outside i_size may be dirtied by __set_page_dirty_buffers;
	 * handle that here by just cleaning them.
	 */

	block = page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	head = page_buffers(page);
	bh = head;

	/*
	 * Get all the dirty buffers mapped to disk addresses and
	 * handle any aliases from the underlying blockdev's mapping.
	 */
	/* ȷ���Ѿ�ӳ�������л����� */
	do {
		if (block > last_block) {/* �������ļ��� */
			/*
			 * mapped buffers outside i_size will occur, because
			 * this page can be outside i_size when there is a
			 * truncate in progress.
			 */
			/*
			 * The buffer was zeroed by block_write_full_page()
			 */
			/* �ϲ�����߱��������ҳ�����ݣ����ｫ���������������������uptodate��־ */
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
		} else if (!buffer_mapped(bh) && buffer_dirty(bh)) {/* �����û��ӳ�䵽���̣����һ�����Ϊ�� */
			/* ��ô����߼��飬��Ҫʱ������ӿ� */
			err = get_block(inode, block, bh, 1);
			if (err)
				goto recover;
			if (buffer_new(bh)) {
				/* blockdev mappings never come here */
				clear_buffer_new(bh);
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
			}
		}
		/* ������һ���������ײ� */
		bh = bh->b_this_page;
		block++;
	} while (bh != head);

	/* ��ס������ */
	do {
		get_bh(bh);
		if (!buffer_mapped(bh))/* �����ļ���С�Ļ�����������Ҫ���� */
			continue;
		/*
		 * If it's a fully non-blocking write attempt and we cannot
		 * lock the buffer then redirty the page.  Note that this can
		 * potentially cause a busy-wait loop from pdflush and kswapd
		 * activity, but those code paths have their own higher-level
		 * throttling.
		 */
		if (wbc->sync_mode != WB_SYNC_NONE || !wbc->nonblocking) {/* Ҫ�������Ļ�д�ļ��������������� */
			/* ���������� */
			lock_buffer(bh);
		} else if (test_set_buffer_locked(bh)) {/* ���Ի������������ܻ�������������һ�������� */
			redirty_page_for_writepage(wbc, page);/* ���±��ҳ��Ϊ�� */
			continue;
		}
		/* ���е��ˣ��Ѿ��ɹ���û������ײ����� */
		if (test_clear_buffer_dirty(bh)) {
			/* ���ҳ��Ϊ�࣬����������ص�������������BH_Async_Write��־���Ժ���д����� */
			mark_buffer_async_write(bh); /*��*/
		} else {
			unlock_buffer(bh);/* ��������໺�����������������д�������� */
		}
	} while ((bh = bh->b_this_page) != head);

	/*
	 * The page and its buffers are protected by PageWriteback(), so we can
	 * drop the bh refcounts early.
	 */
	/* ȷ��û�����û�д��־,������д��־���ϣ���д��־������ҳ������Ŀ黺���� */
	BUG_ON(PageWriteback(page));
	set_page_writeback(page); /*��*/
	unlock_page(page);

	/**
	 * ��ÿ����������submit_bh������ִ��д������
	 */
	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {/* �������࣬��Ҫ�ύ */
			submit_bh(WRITE, bh); /*��*/
			nr_underway++;
		}
		put_bh(bh);
		bh = next;
	} while (bh != head);

	err = 0;
done:
	if (nr_underway == 0) {
		/*
		 * The page was marked dirty, but the buffers were
		 * clean.  Someone wrote them back by hand with
		 * ll_rw_block/submit_bh.  A rare case.
		 */
		int uptodate = 1;
		do {
			if (!buffer_uptodate(bh)) {
				uptodate = 0;
				break;
			}
			bh = bh->b_this_page;
		} while (bh != head);
		if (uptodate)
			SetPageUptodate(page);
		end_page_writeback(page);
		/*
		 * The page and buffer_heads can be released at any time from
		 * here on.
		 */
		wbc->pages_skipped++;	/* We didn't write this page */
	}
	return err;

recover:
	/*
	 * ENOSPC, or some other error.  We may already have added some
	 * blocks to the file, so we need to write these out to avoid
	 * exposing stale data.
	 * The page is currently locked and not marked for writeback
	 */
	bh = head;
	/* Recovery: lock and submit the mapped buffers */
	do {
		get_bh(bh);
		if (buffer_mapped(bh) && buffer_dirty(bh)) {
			lock_buffer(bh);
			mark_buffer_async_write(bh);
		} else {
			/*
			 * The buffer may have been set dirty during
			 * attachment to a dirty page.
			 */
			clear_buffer_dirty(bh);
		}
	} while ((bh = bh->b_this_page) != head);
	SetPageError(page);
	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {
			clear_buffer_dirty(bh);
			submit_bh(WRITE, bh);
			nr_underway++;
		}
		put_bh(bh);
		bh = next;
	} while (bh != head);
	goto done;
}

/**
 * Ϊ�ļ�ҳ�Ļ������ͻ������ײ���׼��
 */
static int __block_prepare_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to, get_block_t *get_block)
{
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	blocksize = 1 << inode->i_blkbits;
	/**
	 * ���ĳҳ�Ƿ���һ��������ҳ���������PG_Private��־��λ����
	 * ���û�����øñ�־�������create_empty_buffersΪҳ�����еĻ��������仺�����ײ�
	 */
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	bbits = inode->i_blkbits;
	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);

	/**
	 * ��ҳ�а����Ļ�������Ӧ��ÿ���������ײ�������д����Ӱ���ÿ���������ײ���
	 */
	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		/**
		 * ���BH_New��־��λ���ͽ�����0��
		 */
		if (buffer_new(bh))
			clear_buffer_new(bh);
		/**
		 * ���BH_New��־�Ѿ���0����
		 */
		if (!buffer_mapped(bh)) {
			/**
			 * get_block�Ǵ��ݹ������������ļ�ϵͳ�ĺ������鿴����ļ�ϵͳ�������ݽṹ�����һ��������߼���š�
			 * ������ڷ�������ʼλ�ö�������ͨ�ļ�����ʼλ�ã�
			 * ���ļ�ϵͳ��صĺ��������������ڶ�Ӧ�������ײ���b_blocknr�ֶΡ�����������BH_Mapped��־��
			 * ���ļ�ϵͳ��صĺ�������Ϊ�ļ�����һ���µ�����飨�磺���ʵĿ�����ļ��ġ������У�����������£�����BH_Newֵ
			 */
			err = get_block(inode, block, bh, 1);
			if (err)
				goto out;
			/**
			 * ���BH_New��־��ֵ
			 */
			if (buffer_new(bh)) {
				clear_buffer_new(bh);
				/**
				 * ������BH_New��־��ֵ������unmap_underlying_metadata���ҳ���ٻ����ڵ�ĳ�����豸������ҳ���Ƿ����ָ�����ͬһ���һ��������
				 * ���ܿ����Բ��󣬵���һ���û�ֱ������豸�ļ�д���ݿ�ʱ�����ǻ��������������Ӷ�Խ���ļ�ϵͳ��
				 * �ú���ʵ���ϵ���__find_get_block��ҳ���ٻ����ڲ���һ���ɿ顣����ҵ�һ�飬������BH_Dirty��־��0���ȴ�ֱ���û�������IO������ϡ�
				 */
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
				if (PageUptodate(page)) {
					set_buffer_uptodate(bh);
					continue;
				}
				/**
				 * ���⣬���д��������������������д������0��дδд����
				 * Ȼ����ҳ�е���һ��������
				 */
				if (block_end > to || block_start < from) {
					void *kaddr;

					kaddr = kmap_atomic(page, KM_USER0);
					if (block_end > to)
						memset(kaddr+to, 0,
							block_end-to);
					if (block_start < from)
						memset(kaddr+block_start,
							0, from-block_start);
					flush_dcache_page(page);
					kunmap_atomic(kaddr, KM_USER0);
				}
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}
		/**
		 * ����д������������������BH_Delay��BH_Uptodate��־δ��λ
		 * �����Ѿ��ڴ����ļ�ϵͳ���ݽṹ�з����˿飬����RAM�Ļ������в�û����Ч������ӳ��
		 * �����Ըÿ����ll_rw_block�Ӵ��̶�ȡ��������
		 */
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		     (block_start < from || block_end > to)) {
			ll_rw_block(READ, 1, &bh);
			*wait_bh++=bh;
		}
	}
	/*
	 * If we issued read requests - let them complete.
	 */
	/**
	 * ������ǰ���̣�ֱ��ll_rw_blockҪ������ж�������ȫ����ɡ�
	 */
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			return -EIO;
	}
	return 0;
out:
	/*
	 * Zero out any newly allocated blocks to avoid exposing stale
	 * data.  If BH_New is set, we know that the block was newly
	 * allocated in the above loop.
	 */
	bh = head;
	block_start = 0;
	do {
		block_end = block_start+blocksize;
		if (block_end <= from)
			goto next_bh;
		if (block_start >= to)
			break;
		if (buffer_new(bh)) {
			void *kaddr;

			clear_buffer_new(bh);
			kaddr = kmap_atomic(page, KM_USER0);
			memset(kaddr+block_start, 0, bh->b_size);
			kunmap_atomic(kaddr, KM_USER0);
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
next_bh:
		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
	return err;
}

static int __block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	blocksize = 1 << inode->i_blkbits;

	/**
	 * ����ҳ����д����Ӱ������л��������������е�ÿ��������������Ӧ�������ײ���BH_Uptodate��BH_Dirty��־��λ��
	 * ���ﲻ�ÿ��������ˣ���Ϊ��generic_file_write������˶����ݵĿ���
	 */
	for(bh = head = page_buffers(page), block_start = 0;
	    bh != head || !block_start;
	    block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
            /*
             * ��Ӧ�������ײ���BH_Uptodate��־��λ��
             * ����__set_page_dirty_nobuffers()��ҳ��PG_dirty��־��λ�����ڻ����н�ҳ���Ϊ��
             */
			mark_buffer_dirty(bh);
		}
	}

	/*
	 * If this is a partial write which happened to make all buffers
	 * uptodate then we can optimize away a bogus readpage() for
	 * the next read(). Here we 'discover' whether the page went
	 * uptodate as a result of this (potentially partial) write.
	 */
	/**
	 * ���������ҳ�е����л����������µģ���PG_uptodate��־��λ��
	 */
	if (!partial)
		SetPageUptodate(page);
	return 0;
}

/*
 * Generic "read page" function for block devices that have the normal
 * get_block functionality. This is most of the block device filesystems.
 * Reads the page asynchronously --- the unlock_buffer() and
 * set/clear_buffer_uptodate() functions propagate buffer state into the
 * page struct once IO has completed.
 */
/**
 * ���豸�ļ���readpage����������ͬ�ģ�������blkdev_readpage����blkdev_readpage����ñ�������
 * get_block��������ļ���ʼ�����ļ����ת��Ϊ����ڿ��豸��ʼ�����߼���š�
 * �����Կ��豸�ļ���˵������������һ�µġ�
 * block_read_full_page��һ�ζ�һ��ķ�ʽ��һҳ���ݡ�
 * �������豸�ļ��ʹ����Ͽ鲻���ڵ���ͨ�ļ�ʱ��ʹ�øú�����
 */
int block_read_full_page(struct page *page, get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize;
	int nr, i;
	int fully_mapped = 1; //�����ļ��Ƿ��пն���fully_mapped = 0 ��ʾ�пն�

	if (!PageLocked(page))
		PAGE_BUG(page);
	blocksize = 1 << inode->i_blkbits;
	/**
	 * ���ҳ�������ı�־PG_private�������λ�����ҳ���������ҳ�Ŀ�Ļ������ײ�������أ��ѿ�����ҳ���ٻ����У�
	 * ���򣬵���create_empty_buffersΪ��ҳ���������п黺�������仺�����ײ���
	 */
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	/**
	 * �������ҳ���ļ�ƫ����(page->index)�����ҳ�е�һ����ļ����iblock�����һ�����������lblock
	 */
	iblock = (sector_t)page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	lblock = (i_size_read(inode)+blocksize-1) >> inode->i_blkbits;
	bh = head;
	nr = 0;
	i = 0;

	/**
	 * �Ը�ҳ��ÿ���������ײ���ִ�����²���
	 */
	do {
		/**
		 * ���BH_Uptodate��λ���������û��������������ҳ����һ��������
		 */
		if (buffer_uptodate(bh))
			continue;

		/**
		 * ���BH_Mappedδ��λ
		 */
		if (!buffer_mapped(bh)) {
			fully_mapped = 0;
			/**
			 * ���Ҹÿ�û�г����ļ�β
			 */
			if (iblock < lblock) {
				/**
				 * �����������ļ�ϵͳ��get_block�������ú�����Ϊ�������롣
				 * ������ͨ�ļ����ú������ļ�ϵͳ�Ĵ������ݽṹ�в��ң��õ�����ڴ��̻������ʼ���Ļ������߼����
				 * ���ڿ��豸�ļ�����ͬ���Ǹú������ļ���ŵ����߼���š�
				 * �����������Σ����������߼���Ŵ������Ӧ�������ײ���b_blocknr�ֶ��У�������־BH_Mapped��־��λ
				 */
				if (get_block(inode, iblock, bh, 0))
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				void *kaddr = kmap_atomic(page, KM_USER0);
				memset(kaddr + i * blocksize, 0, blocksize);
				flush_dcache_page(page);
				kunmap_atomic(kaddr, KM_USER0);
				set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * get_block() might have updated the buffer
			 * synchronously
			 */
			/**
			 * �ٴμ��BH_Uptodate��־����Ϊ�������ļ�ϵͳ��get_block���������Ѿ��Ƿ��˿�IO�����������˻�������
			 * ���BH_Uptodate��λ�ˣ��ͼ���������һ��������
			 */
			if (buffer_uptodate(bh))
				continue;
		}
		/**
		 * ���������ײ��ĵ�ַ����ھֲ�����arr�У�������ҳ����һ��������
		 */
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	/**
	 * ���û�������ļ�����������PG_mappedtodisk��־
	 */
	if (fully_mapped)
		SetPageMappedToDisk(page);

	/**
	 * arr�д����һЩ�������ײ��ĵ�ַ�������Ӧ�Ļ����������ݲ������µġ�
	 * �������Ϊ�գ���ôҳ�����л�����������Ч�ġ���ˣ�����ҳ��PG_uptodate��־
	 */
	if (!nr) {
		/*
		 * All buffers are uptodate - we can set the page uptodate
		 * as well. But not if get_block() returned an error.
		 */
		if (!PageError(page))
			SetPageUptodate(page);
		/**
		 * ����PG_uptodate��־�󣬵���unlock_page�����ء�
		 */
		unlock_page(page);
		return 0;
	}

	/* Stage two: lock the buffers */
	/**
	 * arr�ǿգ��������е�ÿ���������ײ�ִ�����²���
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		/**
		 * ��BH_Lock��λ��һ����λ��������һֱ�ȴ��û������ͷš�
		 */
		lock_buffer(bh);
		/**
		 * ���������ײ���b_end_io�ֶ���Ϊend_buffer_async_read�����ĵ�ַ��
		 * �����������ײ���BH_Async_Read��־��λ
		 */
		mark_buffer_async_read(bh);
	}

	/*
	 * Stage 3: start the IO.  Check for uptodateness
	 * inside the buffer lock in case another process reading
	 * the underlying blockdev brought it uptodate (the sct fix).
	 */
	/**
	 * ��arr�е�ÿ���������ײ�������submit_bh��������������ΪREAD�����ᴥ����Ӧ���IO���ݴ��䡣
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);
		else
			submit_bh(READ, bh);
	}
	/*
	 * ����0
	 */
	return 0;
}

/* utility function for filesystems that need to do work on expanding
 * truncates.  Uses prepare/commit_write to allow the filesystem to
 * deal with the hole.  
 */
int generic_cont_expand(struct inode *inode, loff_t size)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	unsigned long index, offset, limit;
	int err;

	err = -EFBIG;
        limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
	if (limit != RLIM_INFINITY && size > (loff_t)limit) {
		send_sig(SIGXFSZ, current, 0);
		goto out;
	}
	if (size > inode->i_sb->s_maxbytes)
		goto out;

	offset = (size & (PAGE_CACHE_SIZE-1)); /* Within page */

	/* ugh.  in prepare/commit_write, if from==to==start of block, we 
	** skip the prepare.  make sure we never send an offset for the start
	** of a block
	*/
	if ((offset & (inode->i_sb->s_blocksize - 1)) == 0) {
		offset++;
	}
	index = size >> PAGE_CACHE_SHIFT;
	err = -ENOMEM;
	page = grab_cache_page(mapping, index);
	if (!page)
		goto out;
	err = mapping->a_ops->prepare_write(NULL, page, offset, offset);
	if (!err) {
		err = mapping->a_ops->commit_write(NULL, page, offset, offset);
	}
	unlock_page(page);
	page_cache_release(page);
	if (err > 0)
		err = 0;
out:
	return err;
}

/*
 * For moronic filesystems that do not allow holes in file.
 * We may have to extend the file.
 */

int cont_prepare_write(struct page *page, unsigned offset,
		unsigned to, get_block_t *get_block, loff_t *bytes)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct page *new_page;
	pgoff_t pgpos;
	long status;
	unsigned zerofrom;
	unsigned blocksize = 1 << inode->i_blkbits;
	void *kaddr;

	while(page->index > (pgpos = *bytes>>PAGE_CACHE_SHIFT)) {
		status = -ENOMEM;
		new_page = grab_cache_page(mapping, pgpos);
		if (!new_page)
			goto out;
		/* we might sleep */
		if (*bytes>>PAGE_CACHE_SHIFT != pgpos) {
			unlock_page(new_page);
			page_cache_release(new_page);
			continue;
		}
		zerofrom = *bytes & ~PAGE_CACHE_MASK;
		if (zerofrom & (blocksize-1)) {
			*bytes |= (blocksize-1);
			(*bytes)++;
		}
		status = __block_prepare_write(inode, new_page, zerofrom,
						PAGE_CACHE_SIZE, get_block);
		if (status)
			goto out_unmap;
		kaddr = kmap_atomic(new_page, KM_USER0);
		memset(kaddr+zerofrom, 0, PAGE_CACHE_SIZE-zerofrom);
		flush_dcache_page(new_page);
		kunmap_atomic(kaddr, KM_USER0);
		generic_commit_write(NULL, new_page, zerofrom, PAGE_CACHE_SIZE);
		unlock_page(new_page);
		page_cache_release(new_page);
	}

	if (page->index < pgpos) {
		/* completely inside the area */
		zerofrom = offset;
	} else {
		/* page covers the boundary, find the boundary offset */
		zerofrom = *bytes & ~PAGE_CACHE_MASK;

		/* if we will expand the thing last block will be filled */
		if (to > zerofrom && (zerofrom & (blocksize-1))) {
			*bytes |= (blocksize-1);
			(*bytes)++;
		}

		/* starting below the boundary? Nothing to zero out */
		if (offset <= zerofrom)
			zerofrom = offset;
	}
	status = __block_prepare_write(inode, page, zerofrom, to, get_block);
	if (status)
		goto out1;
	if (zerofrom < offset) {
		kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr+zerofrom, 0, offset-zerofrom);
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
		__block_commit_write(inode, page, zerofrom, offset);
	}
	return 0;
out1:
	ClearPageUptodate(page);
	return status;

out_unmap:
	ClearPageUptodate(new_page);
	unlock_page(new_page);
	page_cache_release(new_page);
out:
	return status;
}

/**
 * Ϊ�ļ�ҳ�Ļ������ͻ������ײ���׼��
 */
int block_prepare_write(struct page *page, unsigned from, unsigned to,
			get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	int err = __block_prepare_write(inode, page, from, to, get_block);
	if (err)
		ClearPageUptodate(page);
	return err;
}

int block_commit_write(struct page *page, unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	__block_commit_write(inode,page,from,to);
	return 0;
}

/**
 * address_space�����commit_write��������������������������з���־�ʹ����ļ�ϵͳ��
 */
int generic_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;
	
	__block_commit_write(inode,page,from,to); /*��*/
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_sem.
	 */
	/**
	 * ���д�����Ƿ��ļ������������������ļ������������i_size�ֶΡ�
	 */
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		mark_inode_dirty(inode);
	}
	return 0;
}


/*
 * nobh_prepare_write()'s prereads are special: the buffer_heads are freed
 * immediately, while under the page lock.  So it needs a special end_io
 * handler which does not touch the bh after unlocking it.
 *
 * Note: unlock_buffer() sort-of does touch the bh after unlocking it, but
 * a race there is benign: unlock_buffer() only use the bh's address for
 * hashing after unlocking the buffer, so it doesn't actually touch the bh
 * itself.
 */
static void end_buffer_read_nobh(struct buffer_head *bh, int uptodate)
{
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		/* This happens, due to failed READA attempts. */
		clear_buffer_uptodate(bh);
	}
	unlock_buffer(bh);
}

/*
 * On entry, the page is fully not uptodate.
 * On exit the page is fully uptodate in the areas outside (from,to)
 */
int nobh_prepare_write(struct page *page, unsigned from, unsigned to,
			get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocksize = 1 << blkbits;
	struct buffer_head map_bh;
	struct buffer_head *read_bh[MAX_BUF_PER_PAGE];
	unsigned block_in_page;
	unsigned block_start;
	sector_t block_in_file;
	char *kaddr;
	int nr_reads = 0;
	int i;
	int ret = 0;
	int is_mapped_to_disk = 1;
	int dirtied_it = 0;

	if (PageMappedToDisk(page))
		return 0;

	block_in_file = (sector_t)page->index << (PAGE_CACHE_SHIFT - blkbits);
	map_bh.b_page = page;

	/*
	 * We loop across all blocks in the page, whether or not they are
	 * part of the affected region.  This is so we can discover if the
	 * page is fully mapped-to-disk.
	 */
	for (block_start = 0, block_in_page = 0;
		  block_start < PAGE_CACHE_SIZE;
		  block_in_page++, block_start += blocksize) {
		unsigned block_end = block_start + blocksize;
		int create;

		map_bh.b_state = 0;
		create = 1;
		if (block_start >= to)
			create = 0;
		ret = get_block(inode, block_in_file + block_in_page,
					&map_bh, create);
		if (ret)
			goto failed;
		if (!buffer_mapped(&map_bh))
			is_mapped_to_disk = 0;
		if (buffer_new(&map_bh))
			unmap_underlying_metadata(map_bh.b_bdev,
							map_bh.b_blocknr);
		if (PageUptodate(page))
			continue;
		if (buffer_new(&map_bh) || !buffer_mapped(&map_bh)) {
			kaddr = kmap_atomic(page, KM_USER0);
			if (block_start < from) {
				memset(kaddr+block_start, 0, from-block_start);
				dirtied_it = 1;
			}
			if (block_end > to) {
				memset(kaddr + to, 0, block_end - to);
				dirtied_it = 1;
			}
			flush_dcache_page(page);
			kunmap_atomic(kaddr, KM_USER0);
			continue;
		}
		if (buffer_uptodate(&map_bh))
			continue;	/* reiserfs does this */
		if (block_start < from || block_end > to) {
			struct buffer_head *bh = alloc_buffer_head(GFP_NOFS);

			if (!bh) {
				ret = -ENOMEM;
				goto failed;
			}
			bh->b_state = map_bh.b_state;
			atomic_set(&bh->b_count, 0);
			bh->b_this_page = NULL;
			bh->b_page = page;
			bh->b_blocknr = map_bh.b_blocknr;
			bh->b_size = blocksize;
			bh->b_data = (char *)(long)block_start;
			bh->b_bdev = map_bh.b_bdev;
			bh->b_private = NULL;
			read_bh[nr_reads++] = bh;
		}
	}

	if (nr_reads) {
		struct buffer_head *bh;

		/*
		 * The page is locked, so these buffers are protected from
		 * any VM or truncate activity.  Hence we don't need to care
		 * for the buffer_head refcounts.
		 */
		for (i = 0; i < nr_reads; i++) {
			bh = read_bh[i];
			lock_buffer(bh);
			bh->b_end_io = end_buffer_read_nobh;
			submit_bh(READ, bh);
		}
		for (i = 0; i < nr_reads; i++) {
			bh = read_bh[i];
			wait_on_buffer(bh);
			if (!buffer_uptodate(bh))
				ret = -EIO;
			free_buffer_head(bh);
			read_bh[i] = NULL;
		}
		if (ret)
			goto failed;
	}

	if (is_mapped_to_disk)
		SetPageMappedToDisk(page);
	SetPageUptodate(page);

	/*
	 * Setting the page dirty here isn't necessary for the prepare_write
	 * function - commit_write will do that.  But if/when this function is
	 * used within the pagefault handler to ensure that all mmapped pages
	 * have backing space in the filesystem, we will need to dirty the page
	 * if its contents were altered.
	 */
	if (dirtied_it)
		set_page_dirty(page);

	return 0;

failed:
	for (i = 0; i < nr_reads; i++) {
		if (read_bh[i])
			free_buffer_head(read_bh[i]);
	}

	/*
	 * Error recovery is pretty slack.  Clear the page and mark it dirty
	 * so we'll later zero out any blocks which _were_ allocated.
	 */
	kaddr = kmap_atomic(page, KM_USER0);
	memset(kaddr, 0, PAGE_CACHE_SIZE);
	kunmap_atomic(kaddr, KM_USER0);
	SetPageUptodate(page);
	set_page_dirty(page);
	return ret;
}
EXPORT_SYMBOL(nobh_prepare_write);

int nobh_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to)
{
	struct inode *inode = page->mapping->host;
	loff_t pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	set_page_dirty(page);
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		mark_inode_dirty(inode);
	}
	return 0;
}
EXPORT_SYMBOL(nobh_commit_write);

/*
 * This function assumes that ->prepare_write() uses nobh_prepare_write().
 */
int nobh_truncate_page(struct address_space *mapping, loff_t from)
{
	struct inode *inode = mapping->host;
	unsigned blocksize = 1 << inode->i_blkbits;
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned to;
	struct page *page;
	struct address_space_operations *a_ops = mapping->a_ops;
	char *kaddr;
	int ret = 0;

	if ((offset & (blocksize - 1)) == 0)
		goto out;

	ret = -ENOMEM;
	page = grab_cache_page(mapping, index);
	if (!page)
		goto out;

	to = (offset + blocksize) & ~(blocksize - 1);
	ret = a_ops->prepare_write(NULL, page, offset, to);
	if (ret == 0) {
		kaddr = kmap_atomic(page, KM_USER0);
		memset(kaddr + offset, 0, PAGE_CACHE_SIZE - offset);
		flush_dcache_page(page);
		kunmap_atomic(kaddr, KM_USER0);
		set_page_dirty(page);
	}
	unlock_page(page);
	page_cache_release(page);
out:
	return ret;
}
EXPORT_SYMBOL(nobh_truncate_page);

int block_truncate_page(struct address_space *mapping,
			loff_t from, get_block_t *get_block)
{
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize;
	pgoff_t iblock;
	unsigned length, pos;
	struct inode *inode = mapping->host;
	struct page *page;
	struct buffer_head *bh;
	void *kaddr;
	int err;

	blocksize = 1 << inode->i_blkbits;
	length = offset & (blocksize - 1);

	/* Block boundary? Nothing to do */
	if (!length)
		return 0;

	length = blocksize - length;
	iblock = index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	
	page = grab_cache_page(mapping, index);
	err = -ENOMEM;
	if (!page)
		goto out;

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	err = 0;
	if (!buffer_mapped(bh)) {
		err = get_block(inode, iblock, bh, 0);
		if (err)
			goto unlock;
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh))
			goto unlock;
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh) && !buffer_delay(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
	}

	kaddr = kmap_atomic(page, KM_USER0);
	memset(kaddr + offset, 0, length);
	flush_dcache_page(page);
	kunmap_atomic(kaddr, KM_USER0);

	mark_buffer_dirty(bh);
	err = 0;

unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return err;
}

/*
 * The generic ->writepage function for buffer-backed address_spaces
 */
/**
 * Ext2�ļ�ϵͳ��ʵ�ֵ�writepage������һ��ͨ�õ�block_write_full_page(ext2_writepage->block_write_full_page)�ķ�װ���������ᴫ��һ��get_block����
 * �Կ��豸��˵��������ֱ�ӵ���block_write_full_page�����ǵ���block_write_full_page�ķ�װ����blkdev_writepage����ʵ��writepage
 */
int block_write_full_page(struct page *page, get_block_t *get_block,
			struct writeback_control *wbc)
{
	struct inode * const inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	unsigned offset;
	void *kaddr;

	/* Is the page fully inside i_size? */
	/* ҳ��������ȫ���ļ���Χ�� */
	if (page->index < end_index)
		/* д����ҳ�� */
		return __block_write_full_page(inode, page, get_block, wbc); /*��*/

	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_CACHE_SIZE-1);
	if (page->index >= end_index+1 || !offset) {/* ҳ����ȫ�����ļ��� */
		/*
		 * The page may have dirty, unmapped buffers.  For example,
		 * they may have been added in ext3_writepage().  Make them
		 * freeable here, so the page does not leak.
		 */
		/* ʹ����ҳ��ʧЧ */
		block_invalidatepage(page, 0); /*��*/
		/* ����ҳ�沢�˳� */
		unlock_page(page);
		return 0; /* don't care */
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invokation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	/* ҳ��λ���ļ��������ӳ��ҳ�� */
	kaddr = kmap_atomic(page, KM_USER0);
	/* ������������0�����������д���������� */
	memset(kaddr + offset, 0, PAGE_CACHE_SIZE - offset);
	flush_dcache_page(page); /*��*/
	kunmap_atomic(kaddr, KM_USER0);
	/* ������ҳ��д�뵽���� */
	return __block_write_full_page(inode, page, get_block, wbc); /*��*/
}

sector_t generic_block_bmap(struct address_space *mapping, sector_t block,
			    get_block_t *get_block)
{
	struct buffer_head tmp;
	struct inode *inode = mapping->host;
	tmp.b_state = 0;
	tmp.b_blocknr = 0;
	get_block(inode, block, &tmp, 0);
	return tmp.b_blocknr;
}

/**
 * �����BIO�ϵ�IO���ݴ�����ֹʱ���ں˵���bi_end_io����
 * һ����˵��bi_end_io��end_bio_bh_io_sync
 */
static int end_bio_bh_io_sync(struct bio *bio, unsigned int bytes_done, int err)
{
	/**
	 * ��bi_private�л�û������ײ��ĵ�ַ
	 */
	struct buffer_head *bh = bio->bi_private;

	if (bio->bi_size)
		return 1;

	if (err == -EOPNOTSUPP) {
		set_bit(BIO_EOPNOTSUPP, &bio->bi_flags);
		set_bit(BH_Eopnotsupp, &bh->b_state);
	}

	/**
	 * ���û������ײ���b_end_io����end_buffer_async_read
	 */
	bh->b_end_io(bh, test_bit(BIO_UPTODATE, &bio->bi_flags));
	/**
	 * �ͷ�bio.
	 */
	bio_put(bio);
	return 0;
}

/**
 * ���ں�ͨ�ÿ�㴫��һ���������ײ������ɴ�������һ�����ݿ顣
 * �ú���ֻ����һ���������ã������ݻ������ײ������ݴ���һ��BIO����
 * ��������generic_make_request��
 * rw:		���ݴ��䷽��(������д)
 * bh:		Ҫ�������ݵĿ黺�����ײ���
 */
int submit_bh(int rw, struct buffer_head * bh)
{
	struct bio *bio;
	int ret = 0;

	BUG_ON(!buffer_locked(bh));
	BUG_ON(!buffer_mapped(bh));
	BUG_ON(!bh->b_end_io);

	if (buffer_ordered(bh) && (rw == WRITE))
		rw = WRITE_BARRIER;

	/*
	 * Only clear out a write error when rewriting, should this
	 * include WRITE_SYNC as well?
	 */
	/**
	 * test_set_buffer_req���û������ײ���BH_Req��־���Ա�ʾ�����ٱ����ʹ�һ�Ρ�
	 * ������ݴ��䷽����WRITE���ͽ�BH_Write_EIO��־��0.
	 */
	if (test_set_buffer_req(bh) && (rw == WRITE || rw == WRITE_BARRIER))
		clear_buffer_write_io_error(bh);

	/*
	 * from here on down, it's all bio -- do the initial mapping,
	 * submit_bio -> generic_make_request may further map this bio around
	 */
	/**
	 * ����bio_alloc ����һ���µ�BIO��������
	 */
	bio = bio_alloc(GFP_NOIO, 1); /*��*/

	/**
	 * ���ݻ������ײ������ݳ�ʼ��bio���������ֶΡ�
	 * �ѿ��еĵ�һ�������ĺŸ���bi_sector��(bh->b_blocknr * bh->b_size / 512)
	 * �ѿ��豸�������ĵ�ַ����bi_bdev��
	 * �ѿ��С����bi_size��
	 * ��ʼ��bi_io_vec�ĵ�һ��Ԫ�أ���ʹ�öζ�Ӧ�ڿ黺������
	 * ��bi_vcnt��Ϊ1(ֻ��һ��bio�Ķ�)������bi_idx��Ϊ0.
	 * ��end_bio_bh_io_sync�ĵ�ַ����bi_end_io�ֶΣ����ѻ������ײ��ĵ�ַ����bi_private�ֶΡ�
	 */
	/*��*/ 
	bio->bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;
	bio->bi_io_vec[0].bv_page = bh->b_page;
	bio->bi_io_vec[0].bv_len = bh->b_size;
	bio->bi_io_vec[0].bv_offset = bh_offset(bh);

	bio->bi_vcnt = 1;
	bio->bi_idx = 0;
	bio->bi_size = bh->b_size;

	bio->bi_end_io = end_bio_bh_io_sync;/* ��bio��ɺ����ͷ��� */
	bio->bi_private = bh;

	/**
	 * ����bio�����ü�����
	 */
	bio_get(bio);
	/**
	 * submit_bio��bi_rw��־����Ϊ���ݴ���ķ��򡣸���ÿCPU����page_states�Ա�ʾ����д����������
	 * ����bio����������generic_make_request������
	 */
	submit_bio(rw, bio); /*��*/

	if (bio_flagged(bio, BIO_EOPNOTSUPP))
		ret = -EOPNOTSUPP;

	/**
	 * �ݼ�bio��ʹ�ü���������Ϊbio�����������Ѿ�������IO���ȳ���Ķ��У�����û���ͷ�bio��������
	 */
	bio_put(bio);
	return ret;
	/*
	 * �����bio �ϵ�IO���ݴ�����ֹ��ʱ���ں�ִ��bi_end_io������������bio_put �ͷ�bio ������
	 */
}

/**
 * ll_rw_block: low-level access to block devices (DEPRECATED)
 * @rw: whether to %READ or %WRITE or maybe %READA (readahead)
 * @nr: number of &struct buffer_heads in the array
 * @bhs: array of pointers to &struct buffer_head
 *
 * ll_rw_block() takes an array of pointers to &struct buffer_heads,
 * and requests an I/O operation on them, either a %READ or a %WRITE.
 * The third %READA option is described in the documentation for
 * generic_make_request() which ll_rw_block() calls.
 *
 * This function drops any buffer that it cannot get a lock on (with the
 * BH_Lock state bit), any buffer that appears to be clean when doing a
 * write request, and any buffer that appears to be up-to-date when doing
 * read request.  Further it marks as clean buffers that are processed for
 * writing (the buffer cache won't assume that they are actually clean until
 * the buffer gets unlocked).
 *
 * ll_rw_block sets b_end_io to simple completion handler that marks
 * the buffer up-to-date (if approriate), unlocks the buffer and wakes
 * any waiters. 
 *
 * All of the buffers must be for the same device, and must also be a
 * multiple of the current approved size for the device.
 */
/**
 * ���м������ݿ�����ݴ��䣬��Щ���ݿ鲻һ�����������ڡ�
 * ע��:	��Io���֮ǰ������������ס��
 * rw:		���ݴ���ķ���
 * nr:		Ҫ��������ݿ�Ŀ�������
 * bhs:		ָ��黺��������Ӧ�Ļ������ײ���ָ�����顣
 */
void ll_rw_block(int rw, int nr, struct buffer_head *bhs[])
{
	int i;

	/**
	 * �����л������ײ���ѭ����
	 */
	for (i = 0; i < nr; i++) {
		struct buffer_head *bh = bhs[i];

		/**
		 * ��鲢���û������ײ���BH_Lock��־��
		 * ����������Ѿ�����ס��������һ���ں˿���·���Ѿ����������ݴ��䣬�Ͳ����������������
		 */
		if (test_set_buffer_locked(bh))
			continue;

		/**
		 * �ѻ������ײ���ʹ�ü�����b_count��1.
		 */
		get_bh(bh);//��b_end_io()�еõ����ü�������
		if (rw == WRITE) {
			/**
			 * ������ݴ���ķ�����WRITE�����û������ײ��ķ���b_end_ioָ����end_buffer_write_sync
			 */
			bh->b_end_io = end_buffer_write_sync; /*��*/
			/**
			 * ��鲢����������ײ���BH_Dirty��־��
			 * ����ñ�־û����λ���Ͳ��ذѿ�д����̡�
			 */
			if (test_clear_buffer_dirty(bh)) {
				/**
				 * ��Ҫд�飬����submit_bh�ѻ������ײ����ݵ�ͨ�ÿ�顣
				 */
				submit_bh(WRITE, bh); /*��*/
				continue;
			}
		} else {
			/**
			 * ������ݴ���ķ�����WRITE�����û������ײ��ķ���b_end_ioָ����end_buffer_read_sync
			 */
			bh->b_end_io = end_buffer_read_sync; /*��*/
			/**
			 * ������ݴ��䷽����WRITE�����жϻ������ײ���BH_Uptodate��־�Ƿ���λ������ǣ��Ͳ��شӴ��̶��顣
			 */
			if (!buffer_uptodate(bh)) {
				/**
				 * ��Ҫ���飬����submit_bh�ѻ������ײ����ݵ�ͨ�ÿ�顣
				 */
				submit_bh(rw, bh); /*��*/
				continue;
			}
		}
		/**
		 * ͨ�����BH_Lock��־Ϊ�������ײ�������Ȼ�������еȴ�������Ľ��̡�
		 */
		unlock_buffer(bh);  /*ע�������unlock��Ϊ��û�н�������IO�����Ŀ���еģ�������submit_bh�Ķ�continue�ˣ������ߵ�����*/
		/**
		 * �ݼ��������ײ���b_count�ֶΡ�
		 */
		put_bh(bh);
	}

	/*
	 * ��������ݴ��ͽ���ʱ���ں�ִ�л������ײ���b_end_io����
	 */
}

/*
 * For a data-integrity writeout, we need to wait upon any in-progress I/O
 * and then start new I/O and then wait upon it.  The caller must have a ref on
 * the buffer_head.
 */
int sync_dirty_buffer(struct buffer_head *bh)
{
	int ret = 0;

	WARN_ON(atomic_read(&bh->b_count) < 1);
	lock_buffer(bh);
	if (test_clear_buffer_dirty(bh)) {
		get_bh(bh);
		bh->b_end_io = end_buffer_write_sync;
		ret = submit_bh(WRITE, bh);
		wait_on_buffer(bh);
		if (buffer_eopnotsupp(bh)) {
			clear_buffer_eopnotsupp(bh);
			ret = -EOPNOTSUPP;
		}
		if (!ret && !buffer_uptodate(bh))
			ret = -EIO;
	} else {
		unlock_buffer(bh);
	}
	return ret;
}

/*
 * try_to_free_buffers() checks if all the buffers on this particular page
 * are unused, and releases them if so.
 *
 * Exclusion against try_to_free_buffers may be obtained by either
 * locking the page or by holding its mapping's private_lock.
 *
 * If the page is dirty but all the buffers are clean then we need to
 * be sure to mark the page clean as well.  This is because the page
 * may be against a block device, and a later reattachment of buffers
 * to a dirty page will set *all* buffers dirty.  Which would corrupt
 * filesystem data on the same device.
 *
 * The same applies to regular filesystem pages: if all the buffers are
 * clean then we set the page clean and proceed.  To do that, we require
 * total exclusion from __set_page_dirty_buffers().  That is obtained with
 * private_lock.
 *
 * try_to_free_buffers() is non-blocking.
 */
static inline int buffer_busy(struct buffer_head *bh)
{
	return atomic_read(&bh->b_count) |
		(bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

/*
 * ����������ײ��ڼ�ӻ������������У����������ɾ������
 */
static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh;

	/*
	 * ѭ��ɨ��һ�飬ȷ��û��busy��buffer
	 */
	bh = head;
	do {
		if (buffer_write_io_error(bh))
			set_bit(AS_EIO, &page->mapping->flags);
		if (buffer_busy(bh))
			goto failed; /*��*/
		bh = bh->b_this_page; /*��*/
	} while (bh != head);

    /*
     * ������Ϊѭ��������һȦ����ôbhӦ���ٴ�ָ����head
     */

	/*
	 * ����ɨ��ÿ���������ײ���
	 * ����������ײ��ڼ�ӻ������������У����������ɾ������
	 */
	do {
		struct buffer_head *next = bh->b_this_page;

		if (!list_empty(&bh->b_assoc_buffers))
			__remove_assoc_queue(bh); /*��*/
		bh = next;
	} while (bh != head);
	/*
	 * ��¼�������ײ�����ͷ�ṩ����һ���ͷ�ʹ��
	 */
	*buffers_to_free = head; /*��*/
	/*
	 * ���PG_private ��־���ͷ����ü���
	 */
	__clear_page_buffers(page);

	/*
	 * �ɹ�����1
	 */
	return 1;
failed:
	return 0;
}

/*
 * ����ɨ�軺����ҳ�Ļ������ײ������ͷ�
 */
int try_to_free_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;
	struct buffer_head *buffers_to_free = NULL;
	int ret = 0;

	BUG_ON(!PageLocked(page));
	/**
	 * ���ҳ�����л��������ײ���־���������д�أ�˵�������ͷ���Щ������������0.
	 */
	if (PageWriteback(page))
		return 0;

	if (mapping == NULL) {		/* can this still happen? */
		ret = drop_buffers(page, &buffers_to_free); 
		goto out;
	}

	spin_lock(&mapping->private_lock);
	/**
	 * ����������ײ��ڼ�ӻ������������У����������ɾ������
	 */
	ret = drop_buffers(page, &buffers_to_free); /*��*/
	if (ret) {
		/*
		 * If the filesystem writes its buffers by hand (eg ext3)
		 * then we can have clean buffers against a dirty page.  We
		 * clean the page here; otherwise later reattachment of buffers
		 * could encounter a non-uptodate page, which is unresolvable.
		 * This only applies in the rare case where try_to_free_buffers
		 * succeeds but the page is not freed.
		 */
		/** 
		 * ���ҳ��PG_dirty��־��
		 */
		clear_page_dirty(page); /*��*/
	}
	spin_unlock(&mapping->private_lock);
out:
	if (buffers_to_free) {
		struct buffer_head *bh = buffers_to_free;

		/**
		 * ��������free_buffer_head�����ͷ�ҳ�����л������ײ���
		 */
		do {
			struct buffer_head *next = bh->b_this_page;
			free_buffer_head(bh);   /*��*/
			bh = next;
		} while (bh != buffers_to_free);
	}
	return ret;
}
EXPORT_SYMBOL(try_to_free_buffers);

int block_sync_page(struct page *page)
{
	struct address_space *mapping;

	smp_mb();
	mapping = page_mapping(page);
	if (mapping)
		blk_run_backing_dev(mapping->backing_dev_info, page);
	return 0;
}

/*
 * There are no bdflush tunables left.  But distributions are
 * still running obsolete flush daemons, so we terminate them here.
 *
 * Use of bdflush() is deprecated and will be removed in a future kernel.
 * The `pdflush' kernel threads fully replace bdflush daemons and this call.
 */
asmlinkage long sys_bdflush(int func, long data)
{
	static int msg_count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (msg_count < 5) {
		msg_count++;
		printk(KERN_INFO
			"warning: process `%s' used the obsolete bdflush"
			" system call\n", current->comm);
		printk(KERN_INFO "Fix your initscripts?\n");
	}

	if (func == 1)
		do_exit(0);
	return 0;
}

/*
 * Buffer-head allocation
 */
/**
 * �������ײ������Լ���slab���������ٻ��档��������kmem_cache_s����ڱ���bh_cachep��
 */
static kmem_cache_t *bh_cachep;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
static int max_buffer_heads;

int buffer_heads_over_limit;

struct bh_accounting {
	int nr;			/* Number of live bh's */
	int ratelimit;		/* Limit cacheline bouncing */
};

static DEFINE_PER_CPU(struct bh_accounting, bh_accounting) = {0, 0};

static void recalc_bh_state(void)
{
	int i;
	int tot = 0;

	if (__get_cpu_var(bh_accounting).ratelimit++ < 4096)
		return;
	__get_cpu_var(bh_accounting).ratelimit = 0;
	for_each_cpu(i)
		tot += per_cpu(bh_accounting, i).nr;
	buffer_heads_over_limit = (tot > max_buffer_heads);
}

/**
 * �������ײ����Լ���slab��������bh_cachep
 * alloc_buffer_head�������ڻ�ȡ�������ײ�
 */
struct buffer_head *alloc_buffer_head(int gfp_flags)
{
	struct buffer_head *ret = kmem_cache_alloc(bh_cachep, gfp_flags); /*��*/
	if (ret) {
		preempt_disable();
		__get_cpu_var(bh_accounting).nr++;
		recalc_bh_state();
		preempt_enable();
	}
	return ret;
}
EXPORT_SYMBOL(alloc_buffer_head);

/**
 * �ͷŻ������ײ���
 */
void free_buffer_head(struct buffer_head *bh)
{
	BUG_ON(!list_empty(&bh->b_assoc_buffers));
	kmem_cache_free(bh_cachep, bh); /*��*/
	preempt_disable();
	__get_cpu_var(bh_accounting).nr--;
	recalc_bh_state();
	preempt_enable();
}
EXPORT_SYMBOL(free_buffer_head);

static void
init_buffer_head(void *data, kmem_cache_t *cachep, unsigned long flags)
{
	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
			    SLAB_CTOR_CONSTRUCTOR) {
		struct buffer_head * bh = (struct buffer_head *)data;

		memset(bh, 0, sizeof(*bh));
		INIT_LIST_HEAD(&bh->b_assoc_buffers);
	}
}

#ifdef CONFIG_HOTPLUG_CPU
static void buffer_exit_cpu(int cpu)
{
	int i;
	struct bh_lru *b = &per_cpu(bh_lrus, cpu);

	for (i = 0; i < BH_LRU_SIZE; i++) {
		brelse(b->bhs[i]);
		b->bhs[i] = NULL;
	}
}

static int buffer_cpu_notify(struct notifier_block *self,
			      unsigned long action, void *hcpu)
{
	if (action == CPU_DEAD)
		buffer_exit_cpu((unsigned long)hcpu);
	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */

void __init buffer_init(void)
{
	int nrpages;

	bh_cachep = kmem_cache_create("buffer_head",
			sizeof(struct buffer_head), 0,
			SLAB_PANIC, init_buffer_head, NULL);

	/*
	 * Limit the bh occupancy to 10% of ZONE_NORMAL
	 */
	nrpages = (nr_free_buffer_pages() * 10) / 100;
	max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
	hotcpu_notifier(buffer_cpu_notify, 0);
}

EXPORT_SYMBOL(__bforget);
EXPORT_SYMBOL(__brelse);
EXPORT_SYMBOL(__wait_on_buffer);
EXPORT_SYMBOL(block_commit_write);
EXPORT_SYMBOL(block_prepare_write);
EXPORT_SYMBOL(block_read_full_page);
EXPORT_SYMBOL(block_sync_page);
EXPORT_SYMBOL(block_truncate_page);
EXPORT_SYMBOL(block_write_full_page);
EXPORT_SYMBOL(cont_prepare_write);
EXPORT_SYMBOL(end_buffer_async_write);
EXPORT_SYMBOL(end_buffer_read_sync);
EXPORT_SYMBOL(end_buffer_write_sync);
EXPORT_SYMBOL(file_fsync);
EXPORT_SYMBOL(fsync_bdev);
EXPORT_SYMBOL(generic_block_bmap);
EXPORT_SYMBOL(generic_commit_write);
EXPORT_SYMBOL(generic_cont_expand);
EXPORT_SYMBOL(init_buffer);
EXPORT_SYMBOL(invalidate_bdev);
EXPORT_SYMBOL(ll_rw_block);
EXPORT_SYMBOL(mark_buffer_dirty);
EXPORT_SYMBOL(submit_bh);
EXPORT_SYMBOL(sync_dirty_buffer);
EXPORT_SYMBOL(unlock_buffer);
