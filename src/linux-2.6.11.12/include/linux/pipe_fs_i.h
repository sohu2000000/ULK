#ifndef _LINUX_PIPE_FS_I_H
#define _LINUX_PIPE_FS_I_H

#define PIPEFS_MAGIC 0x50495045

#define PIPE_BUFFERS (16)

/*
 * pipe_inode_info数据结构的bufs字段存放一个具有16个pipe_buffer对象的数据，每个对象代表一个管道缓冲区
 */
struct pipe_buffer {
    /*管道缓冲区页框的描述符地址*/
	struct page *page;
    /*
     * offset：页框内有效数据的当前位置
     * len: 页框内有效数据的长度
     */
	unsigned int offset, len;
    /*
     * 管道缓冲区方法的地址(管道缓冲区空时为NULL),指向anon_pipe_buf_ops
     */
	struct pipe_buf_operations *ops;
};

struct pipe_buf_operations {
	int can_merge;
    /* 在访问缓冲区数据之前调用。它只在管理缓冲区在高端内存时对管理缓冲区页框调用kmap */
	void * (*map)(struct file *, struct pipe_inode_info *, struct pipe_buffer *);
    /* 与map对应,对管理缓冲区页框调用kunmap */
	void (*unmap)(struct pipe_inode_info *, struct pipe_buffer *);
    /* 当释放管道缓冲区时调用，该方法实现了一个单页内存高速缓存。
     * 释放的不是存放缓冲区的那个页框，而是由pipe_inode_info数据结构(如果不是NULL)的tmp_page字段指向的高速缓存页框
     * 存放缓冲区的页框变成新的高速缓存页框
     */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct pipe_inode_info {
    /*管道FIFO等待队列*/
	wait_queue_head_t wait;
    /*
     * nrbufs：包含待读数据的缓冲区数
     * curbufs: 包含待读数据的第一个缓冲区的索引
     */
	unsigned int nrbufs, curbuf;
    /* 管道缓冲区描述符数组*/
	struct pipe_buffer bufs[PIPE_BUFFERS];
    /* 高速缓存页框指针*/
	struct page *tmp_page;
    /* 当前管道缓冲区读的位置*/
	unsigned int start;
    /* 读进程的标准(或编号)*/
	unsigned int readers;
    /* 写进程的标准(或编号)*/
	unsigned int writers;
    /* 在等待队列中睡眠的写进程的个数*/
	unsigned int waiting_writers;
    /* 与readers类似，但当等待读取FIFO的进程时使用*/
	unsigned int r_counter;
    /* 与writers类似，但当等待写入FIFO的进程时使用*/
	unsigned int w_counter;
    /* 用于通过信号进行的异步IO通知*/
	struct fasync_struct *fasync_readers;
    /* 用于通过信号进行的异步IO通知*/
	struct fasync_struct *fasync_writers;
};

/* Differs from PIPE_BUF in that PIPE_SIZE is the length of the actual
   memory allocation, whereas PIPE_BUF makes atomicity guarantees.  */
#define PIPE_SIZE		PAGE_SIZE

#define PIPE_SEM(inode)		(&(inode).i_sem)
#define PIPE_WAIT(inode)	(&(inode).i_pipe->wait)
#define PIPE_BASE(inode)	((inode).i_pipe->base)
#define PIPE_START(inode)	((inode).i_pipe->start)
#define PIPE_LEN(inode)		((inode).i_pipe->len)
#define PIPE_READERS(inode)	((inode).i_pipe->readers)
#define PIPE_WRITERS(inode)	((inode).i_pipe->writers)
#define PIPE_WAITING_WRITERS(inode)	((inode).i_pipe->waiting_writers)
#define PIPE_RCOUNTER(inode)	((inode).i_pipe->r_counter)
#define PIPE_WCOUNTER(inode)	((inode).i_pipe->w_counter)
#define PIPE_FASYNC_READERS(inode)     (&((inode).i_pipe->fasync_readers))
#define PIPE_FASYNC_WRITERS(inode)     (&((inode).i_pipe->fasync_writers))

/* Drop the inode semaphore and wait for a pipe event, atomically */
void pipe_wait(struct inode * inode);

struct inode* pipe_new(struct inode* inode);
void free_pipe_info(struct inode* inode);

#endif
