/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _LIBETH_MEM_H_
#define _LIBETH_MEM_H_

#define BAR0 0
#define wr32 libeth_write32

/**
 * struct libeth_dma_mem - structure for dma memory
 * @va: virtual address
 * @pa: physical address
 * @size: dma memory size
 */
struct libeth_dma_mem {
	void *va;
	dma_addr_t pa;
	size_t size;
};

/**
 * struct libeth_mmio_region - structure for mmio region info
 * @addr: mapped address of the bar + offset
 * @start_offset: start offset of the mmio region
 * @size: size of the region
 */
struct libeth_mmio_region {
	volatile void __iomem *  addr;
	u64 start_offset;
	size_t size;
};

struct libeth_hw;
struct virtchnl2_mem_region;

void *libeth_alloc_dma_mem(struct libeth_hw *hw, struct libeth_dma_mem *mem, u64 size);
void libeth_free_dma_mem(struct libeth_hw *hw, struct libeth_dma_mem *mem);
void __iomem * libeth_get_mmio_addr(struct libeth_hw *hw, u64 region_offset);
u32 libeth_read32(struct libeth_hw *hw, u32 offset);
void libeth_write32(struct libeth_hw *hw, u32 offset, u32 value);
u64 libeth_read64(struct libeth_hw *hw, u32 offset);
void libeth_write64(struct libeth_hw *hw, u32 offset, u64 value);
int libeth_map_bar_region(struct libeth_hw *hw, struct pci_dev *pdev,
			  struct virtchnl2_mem_region *mem_region);

#endif /* _LIBETH_MEM_H_ */
