/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/cdev.h>

/* sysctl tunables... */
/**
 * 可分配的文件对象的最大数目。可通过/proc/sys/fs/file-max文件来修改这个值。
 * max_files指定了可分配文件对象的最大数目
 * 
 * 在内核初始化期间，files_init函数把max_files字段设置为可用RAM大小的1/10
 * 即使max_files文件对象已经被分配，超级用户也总是可以获得一个文件对象
 */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

EXPORT_SYMBOL(files_stat); /* Needed by unix.o */

/* public. Not pretty! */
 __cacheline_aligned_in_smp DEFINE_SPINLOCK(files_lock);

static DEFINE_SPINLOCK(filp_count_lock);

/* slab constructors and destructors are called from arbitrary
 * context and must be fully threaded - use a local spinlock
 * to protect files_stat.nr_files
 */
void filp_ctor(void * objp, struct kmem_cache_s *cachep, unsigned long cflags)
{
	if ((cflags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR) {
		unsigned long flags;
		spin_lock_irqsave(&filp_count_lock, flags);
		files_stat.nr_files++;
		spin_unlock_irqrestore(&filp_count_lock, flags);
	}
}

void filp_dtor(void * objp, struct kmem_cache_s *cachep, unsigned long dflags)
{
	unsigned long flags;
	spin_lock_irqsave(&filp_count_lock, flags);
	files_stat.nr_files--;
	spin_unlock_irqrestore(&filp_count_lock, flags);
}

static inline void file_free(struct file *f)
{
	kmem_cache_free(filp_cachep, f);
}

/* Find an unused file structure and return a pointer to it.
 * Returns NULL, if there are no more free file structures or
 * we run out of memory.
 */
/**
 * get_empty_filp为pipefs文件系统中的管道分配一个索引节点对象并对其进行初始化。
 */
struct file *get_empty_filp(void)
{
	static int old_max;
	struct file * f;

	/*
	 * Privileged users can go above max_files
	 */
	if (files_stat.nr_files < files_stat.max_files ||
				capable(CAP_SYS_ADMIN)) {
		/**
		 * 分配文件索引结点
		 */
		f = kmem_cache_alloc(filp_cachep, GFP_KERNEL);
		if (f) {
			/*
			 * 初始化相关成员
			 */
			memset(f, 0, sizeof(*f));
			if (security_file_alloc(f)) {
				file_free(f);
				goto fail;
			}
			eventpoll_init_file(f);
			atomic_set(&f->f_count, 1);
			f->f_uid = current->fsuid;
			f->f_gid = current->fsgid;
			rwlock_init(&f->f_owner.lock);
			/* f->f_version: 0 */
			INIT_LIST_HEAD(&f->f_list);
			f->f_maxcount = INT_MAX;
			return f;
		}
	}

	/* Ran out of filps - report that */
	if (files_stat.max_files >= old_max) {
		printk(KERN_INFO "VFS: file-max limit %d reached\n",
					files_stat.max_files);
		old_max = files_stat.max_files;
	} else {
		/* Big problems... */
		printk(KERN_WARNING "VFS: filp allocation failed\n");
	}
fail:
	return NULL;
}

EXPORT_SYMBOL(get_empty_filp);

/**
 * 当内核路径完成对文件对象的使用时，调用内核提供的fput()函数
 * 释放对file的引用。
 */
void fastcall fput(struct file *file)
{
    /*
     * 减少f_count的值，如果该字段为0，进行文件释放的一系列操作
	 */
	if (atomic_dec_and_test(&file->f_count))
		__fput(file);
}

EXPORT_SYMBOL(fput);

/* __fput is called from task context when aio completion releases the last
 * last use of a struct file *.  Do not use otherwise.
 */
void fastcall __fput(struct file *file)
{
	struct dentry *dentry = file->f_dentry;
	struct vfsmount *mnt = file->f_vfsmnt;
	struct inode *inode = dentry->d_inode;

	might_sleep();
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);
	locks_remove_flock(file);

    /*
     * 调用文件操作的release方法
	 */
	if (file->f_op && file->f_op->release)
		file->f_op->release(inode, file);
	security_file_free(file);
	if (unlikely(inode->i_cdev != NULL))
		cdev_put(inode->i_cdev);
	fops_put(file->f_op);
	if (file->f_mode & FMODE_WRITE)/* 可写方式打开 */
		put_write_access(inode);/* 减少i_writecount计数 */
	/*
	 * 将文件从超级快的链表中移除
	 */
	file_kill(file);
	file->f_dentry = NULL;
	file->f_vfsmnt = NULL;
	/*
	 * 释放文件对象给slab分配器
	 */
	file_free(file);
	/*
	 * 减少相关的文件系统描述符的目录项对象的引用计数器的值
	 */
	dput(dentry);
	mntput(mnt);
}

/**
 * 当内核开始使用一个文件对象时，内核提供fget()函数以供调用
 * 根据进程文件描述符获得文件对象的地址。并增加其引用计数。
 */
struct file fastcall *fget(unsigned int fd)
{
	struct file *file;
	struct files_struct *files = current->files;

	spin_lock(&files->file_lock);
	file = fcheck_files(files, fd);
	if (file)
		get_file(file);
	spin_unlock(&files->file_lock);
	return file;
}

EXPORT_SYMBOL(fget);

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared. 
 * You can use this only if it is guranteed that the current task already 
 * holds a refcnt to that file. That check has to be done at fget() only
 * and a flag is returned to be passed to the corresponding fput_light().
 * There must not be a cloning between an fget_light/fput_light pair.
 */
/*
 * fget的快速版本，前提是能够假设当前进程已经拥有文件对象，由于先前的open已经增加了文件对象引用计数的值
 */
struct file fastcall *fget_light(unsigned int fd, int *fput_needed)
{
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	if (likely((atomic_read(&files->count) == 1))) {
		file = fcheck_files(files, fd);
	} else {
		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
			get_file(file);
			*fput_needed = 1;
		}
		spin_unlock(&files->file_lock);
	}
	return file;
}


void put_filp(struct file *file)
{
	if (atomic_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_kill(file);
		file_free(file);
	}
}

void file_move(struct file *file, struct list_head *list)
{
	if (!list)
		return;
	file_list_lock();
	list_move(&file->f_list, list);
	file_list_unlock();
}

void file_kill(struct file *file)
{
	if (!list_empty(&file->f_list)) {
		file_list_lock();
		list_del_init(&file->f_list);
		file_list_unlock();
	}
}

int fs_may_remount_ro(struct super_block *sb)
{
	struct list_head *p;

	/* Check that no files are currently opened for writing. */
	file_list_lock();
	list_for_each(p, &sb->s_files) {
		struct file *file = list_entry(p, struct file, f_list);
		struct inode *inode = file->f_dentry->d_inode;

		/* File with pending delete? */
		if (inode->i_nlink == 0)
			goto too_bad;

		/* Writeable file? */
		if (S_ISREG(inode->i_mode) && (file->f_mode & FMODE_WRITE))
			goto too_bad;
	}
	file_list_unlock();
	return 1; /* Tis' cool bro. */
too_bad:
	file_list_unlock();
	return 0;
}

void __init files_init(unsigned long mempages)
{ 
	int n; 
	/* One file with associated inode and dcache is very roughly 1K. 
	 * Per default don't use more than 10% of our memory for files. 
	 */ 

	n = (mempages * (PAGE_SIZE / 1024)) / 10;
	files_stat.max_files = n; 
	if (files_stat.max_files < NR_FILE)
		files_stat.max_files = NR_FILE;
} 
