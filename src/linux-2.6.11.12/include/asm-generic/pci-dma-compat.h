/* include this file if the platform implements the dma_ DMA Mapping API
 * and wants to provide the pci_ DMA Mapping API in terms of it */

#ifndef _ASM_GENERIC_PCI_DMA_COMPAT_H
#define _ASM_GENERIC_PCI_DMA_COMPAT_H

#include <linux/dma-mapping.h>

/* note pci_set_dma_mask isn't here, since it's a public function
 * exported from drivers/pci, use dma_supported instead */

static inline int
pci_dma_supported(struct pci_dev *hwdev, u64 mask)
{
	return dma_supported(hwdev == NULL ? NULL : &hwdev->dev, mask);
}

/**
 * 建立一致性映射。
 *		hwdev:		device结构。
 *		size:		所需要的缓冲区的大小。
 *		dma_handle:	保存相关的总线地址。
 * 返回值是缓冲区的内核虚拟地址。
 * 返回新缓冲区的线性地址和总线地址,在x86中，返回新缓冲区的线性地址和物理地址
 */
static inline void *
pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
		     dma_addr_t *dma_handle)
{
	return dma_alloc_coherent(hwdev == NULL ? NULL : &hwdev->dev, size, dma_handle, GFP_ATOMIC);
}

/*
 * 释放映射和缓冲区
 */
static inline void
pci_free_consistent(struct pci_dev *hwdev, size_t size,
		    void *vaddr, dma_addr_t dma_handle)
{
	dma_free_coherent(hwdev == NULL ? NULL : &hwdev->dev, size, vaddr, dma_handle);
}

/**
 * 映射单个流式缓冲区。建立流式DMA映射，接收缓冲区的线性得至作为其参数
 * 返回值是总线地址。
 */
static inline dma_addr_t
pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction)
{
	return dma_map_single(hwdev == NULL ? NULL : &hwdev->dev, ptr, size, (enum dma_data_direction)direction);
}

/**
 * 解除单个DMA流式映射。这个函数可能会处理回弹缓冲区。
 */
static inline void
pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,
		 size_t size, int direction)
{
	dma_unmap_single(hwdev == NULL ? NULL : &hwdev->dev, dma_addr, size, (enum dma_data_direction)direction);
}

/*
 * 建立高端内存的缓冲区用于DMA传送，传递的参数是页的描述符地址和页中缓冲区的偏移量
 */
static inline dma_addr_t
pci_map_page(struct pci_dev *hwdev, struct page *page,
	     unsigned long offset, size_t size, int direction)
{
	return dma_map_page(hwdev == NULL ? NULL : &hwdev->dev, page, offset, size, (enum dma_data_direction)direction);
}

/*
 * 释放高端内存的缓冲区映射
 */
static inline void
pci_unmap_page(struct pci_dev *hwdev, dma_addr_t dma_address,
	       size_t size, int direction)
{
	dma_unmap_page(hwdev == NULL ? NULL : &hwdev->dev, dma_address, size, (enum dma_data_direction)direction);
}

static inline int
pci_map_sg(struct pci_dev *hwdev, struct scatterlist *sg,
	   int nents, int direction)
{
	return dma_map_sg(hwdev == NULL ? NULL : &hwdev->dev, sg, nents, (enum dma_data_direction)direction);
}

static inline void
pci_unmap_sg(struct pci_dev *hwdev, struct scatterlist *sg,
	     int nents, int direction)
{
	dma_unmap_sg(hwdev == NULL ? NULL : &hwdev->dev, sg, nents, (enum dma_data_direction)direction);
}

/**
 * 当驱动程序不经过撤销流式映射，而想访问DMA缓冲区中的内容时，使用本函数。
 * 这样CPU将暂时拥有该缓冲区。使相应的硬件高速缓存行无效
 */
static inline void
pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle,
		    size_t size, int direction)
{
	dma_sync_single_for_cpu(hwdev == NULL ? NULL : &hwdev->dev, dma_handle, size, (enum dma_data_direction)direction);
}

/**
 * 驱动程序在开始从RAM到设备DMA数据传送之前，调用该函数
 * 刷新与DMA缓冲区对应的高速缓存行 
 */
static inline void
pci_dma_sync_single_for_device(struct pci_dev *hwdev, dma_addr_t dma_handle,
		    size_t size, int direction)
{
	dma_sync_single_for_device(hwdev == NULL ? NULL : &hwdev->dev, dma_handle, size, (enum dma_data_direction)direction);
}

/**
 * 使高速缓存行无效。
 */
static inline void
pci_dma_sync_sg_for_cpu(struct pci_dev *hwdev, struct scatterlist *sg,
		int nelems, int direction)
{
	dma_sync_sg_for_cpu(hwdev == NULL ? NULL : &hwdev->dev, sg, nelems, (enum dma_data_direction)direction);
}

static inline void
pci_dma_sync_sg_for_device(struct pci_dev *hwdev, struct scatterlist *sg,
		int nelems, int direction)
{
	dma_sync_sg_for_device(hwdev == NULL ? NULL : &hwdev->dev, sg, nelems, (enum dma_data_direction)direction);
}

static inline int
pci_dma_mapping_error(dma_addr_t dma_addr)
{
	return dma_mapping_error(dma_addr);
}

#endif
