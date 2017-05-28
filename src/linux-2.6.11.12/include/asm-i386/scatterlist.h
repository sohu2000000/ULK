#ifndef _I386_SCATTERLIST_H
#define _I386_SCATTERLIST_H

/**
 * ������ɢ���ۼ�ӳ���У�ÿ������ҳ�档
 */
struct scatterlist {
	/**
	 * ��������ҳ�档
	 */
    struct page		*page;
	/**
	 * ��������ҳ�ڵ�ƫ�ơ�
	 */
    unsigned int	offset;
    dma_addr_t		dma_address;
	/**
	 * ��������ҳ�ڵĳ��ȡ�
	 */
    unsigned int	length;
};

/* These macros should be used after a pci_map_sg call has been done
 * to get bus addresses of each of the SG entries and their lengths.
 * You should only work with the number of sg entries pci_map_sg
 * returns.
 */
/**
 * �ӷ�ɢ���������з���DMA���ߵ�ַ��
 */
#define sg_dma_address(sg)	((sg)->dma_address)
/**
 * �ӷ�ɢ���������з���DMA�������ĳ��ȡ�
 */
#define sg_dma_len(sg)		((sg)->length)

#define ISA_DMA_THRESHOLD (0x00ffffff)

#endif /* !(_I386_SCATTERLIST_H) */
