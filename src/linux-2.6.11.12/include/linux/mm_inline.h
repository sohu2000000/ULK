/**
 * ��ҳ����������Ļ����ͷ����������������������nr_active�ֶ�
 */
static inline void
add_page_to_active_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->active_list);
	zone->nr_active++;
}

/**
 * ��ҳ����������ķǻ����ͷ����������������������nr_inactive�ֶ�
 */
static inline void
add_page_to_inactive_list(struct zone *zone, struct page *page)
{
	list_add(&page->lru, &zone->inactive_list);
	zone->nr_inactive++;
}

/**
 * �ӹ������Ļ������ɾ��ҳ���ݼ���������������nr_active
 */
static inline void
del_page_from_active_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_active--;
}

/**
 * �ӹ������ķǻ������ɾ��ҳ���ݼ���������������nr_active
 */
static inline void
del_page_from_inactive_list(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	zone->nr_inactive--;
}

/**
 * ���ҳ��PG_active��־�����ݼ������������Ӧ�ı�־��
 * ����ҳ��lru������ɾ��
 * 
 */
static inline void
del_page_from_lru(struct zone *zone, struct page *page)
{
	list_del(&page->lru);
	if (PageActive(page)) {
		ClearPageActive(page);
		zone->nr_active--;
	} else {
		zone->nr_inactive--;
	}
}
