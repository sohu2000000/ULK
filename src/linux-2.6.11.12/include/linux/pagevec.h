/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

/* 14 pointers + two long's align the pagevec structure to a power of two */
#define PAGEVEC_SIZE	14

struct page;
struct address_space;

/*
 * lru_cache_add 和 lru_cache_add_active 并没有立刻把页移动到LRU，而是在pagevec类型的临时数据结构中聚集这些页
 * 每个结构可以存放多达14个页描述符指针。只有当一个pgaevec结构写满了，页才真正被移动到LRU链表中
 * 这种机制可以改善系统性能，因为只有当LRU链表实际修改后才获得LRU自旋锁
 */
struct pagevec {
	unsigned long nr;
	unsigned long cold;
	struct page *pages[PAGEVEC_SIZE];
};

void __pagevec_release(struct pagevec *pvec);
void __pagevec_release_nonlru(struct pagevec *pvec);
void __pagevec_free(struct pagevec *pvec);
void __pagevec_lru_add(struct pagevec *pvec);
void __pagevec_lru_add_active(struct pagevec *pvec);
void pagevec_strip(struct pagevec *pvec);
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages);
unsigned pagevec_lookup_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, int tag,
		unsigned nr_pages);

static inline void pagevec_init(struct pagevec *pvec, int cold)
{
	pvec->nr = 0;
	pvec->cold = cold;
}

static inline void pagevec_reinit(struct pagevec *pvec)
{
	pvec->nr = 0;
}

static inline unsigned pagevec_count(struct pagevec *pvec)
{
	return pvec->nr;
}

static inline unsigned pagevec_space(struct pagevec *pvec)
{
	return PAGEVEC_SIZE - pvec->nr;
}

/*
 * Add a page to a pagevec.  Returns the number of slots still available.
 */
/*
 * 将一个新页添加到一个给出的页向量
 */ 
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	pvec->pages[pvec->nr++] = page;
	return pagevec_space(pvec);
}

/*
 * 将向量中所有页的使用计数器减1.如果某些页的使用计数器归0，即不再使用，则自动返回到伙伴系统。
 * 如果页在系统的某个LRU链表上，则从链表移除，无论其使用计数器为何值
 */
static inline void pagevec_release(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release(pvec);
}

/*
 * 用于是否页的函数，它将一个给定向量中所有页的使用计数器减1。在计数器归0时，对应页占用的内存将返还给伙伴系统。
 * 与pagevec_release不同，该函数假定向量中所有的页都不在任何LRU链表上
 */
static inline void pagevec_release_nonlru(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_release_nonlru(pvec);
}

/*
 * 将一组页占用的内存空间返回给伙伴系统。调用者负责确认页面的使用计数器为0
 */
static inline void pagevec_free(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_free(pvec);
}

static inline void pagevec_lru_add(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);
}
