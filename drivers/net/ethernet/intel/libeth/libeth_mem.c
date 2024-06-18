// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/libeth_controlq.h>

/**
 * libeth_alloc_dma_mem - Allocate dma memory
 * @hw: pointer to hw struct
 * @mem: pointer to dma_mem struct
 * @size: size of the memory to allocate
 */
void *libeth_alloc_dma_mem(struct libeth_hw *hw, struct libeth_dma_mem *mem,
			   u64 size)
{
	struct pci_dev *pdev = hw->pdev;
	size_t sz = ALIGN(size, 4096);

	mem->va = dma_alloc_coherent(&pdev->dev, sz,
				     &mem->pa, GFP_KERNEL);
	mem->size = sz;

	return mem->va;
}
EXPORT_SYMBOL_NS_GPL(libeth_alloc_dma_mem, LIBETH);

/**
 * libeth_free_dma_mem - Free the allocated dma memory
 * @hw: pointer to hw struct
 * @mem: pointer to dma_mem struct
 */
void libeth_free_dma_mem(struct libeth_hw *hw, struct libeth_dma_mem *mem)
{
	struct pci_dev *pdev = hw->pdev;

	dma_free_coherent(&pdev->dev, mem->size,
			  mem->va, mem->pa);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_free_dma_mem, LIBETH);

/**
 * libeth_get_mmio_addr - get the mmio virtual address
 * @hw: hardware specific structure
 * @region_offset: mmio offset
 */
void __iomem *
libeth_get_mmio_addr(struct libeth_hw *hw,
		     u64 region_offset)
{
	int i;

	for (i = 0; i < hw->num_regions; i++) {
		struct libeth_mmio_region *region = &hw->mem_regions[i];

		if (!region->addr)
			continue;

		if (region_offset >= region->start_offset &&
		    region_offset < (region->start_offset + region->size)) {
			region_offset -= region->start_offset;

			return (u8 __iomem *)(region->addr + region_offset);
		}
	}

	return NULL;
}
EXPORT_SYMBOL(libeth_get_mmio_addr);

/**
 * libeth_read32 - memory read 32
 * @hw: hardware specific structure
 * @offset: memory offset
 */
u32 libeth_read32(struct libeth_hw *hw, u32 offset)
{
	volatile void __iomem *addr;

	addr = libeth_get_mmio_addr(hw, offset);
	if (!addr)
		return 0xFFFFFFFF;
	return readl(addr);
}
EXPORT_SYMBOL(libeth_read32);

/**
 * libeth_write32 - memory write 32
 * @hw: hardware specific structure
 * @offset: memory offset
 * @value: value to be written
 */
void libeth_write32(struct libeth_hw *hw, u32 offset, u32 value)
{
	volatile void __iomem *addr;

	addr = libeth_get_mmio_addr(hw, offset);
	if (!addr)
		return;
	writel(value, addr);
}
EXPORT_SYMBOL(libeth_write32);

/**
 * libeth_read64 - memory read 64
 * @hw: hardware specific structure
 * @offset: memory offset
 */
u64 libeth_read64(struct libeth_hw *hw, u32 offset)
{
	volatile void __iomem *addr;

	addr = libeth_get_mmio_addr(hw, offset);
	if (!addr)
		return 0xFFFFFFFFFFFFFFFF;
	return readq(addr);
}
EXPORT_SYMBOL(libeth_read64);

/**
 * libeth_write64 - memory write 64
 * @hw: hardware specific structure
 * @offset: memory offset
 * @value: value to be written
 */
void libeth_write64(struct libeth_hw *hw, u32 offset, u64 value)
{
	volatile void __iomem *addr;

	addr = libeth_get_mmio_addr(hw, offset);
	if (!addr)
		return;
	writeq(value, addr);
}
EXPORT_SYMBOL(libeth_write64);

/**
 * libeth_map_bar_region - map bar region
 * @hw: Hardware specific structure
 * @pdev: pci device
 * @mem_region: region to be mapped
 */
int libeth_map_bar_region(struct libeth_hw *hw, struct pci_dev *pdev,
			  struct virtchnl2_mem_region *mem_region)
{

	resource_size_t pa;
	void __iomem *va;
	u64 offset, size;
	int i;

	offset = le64_to_cpu(mem_region->start_offset);
	size = le64_to_cpu(mem_region->size); 
	
	pa = pci_resource_start(pdev, BAR0) + offset;
	va = ioremap(pa, size);
	if (!va) {
		pci_err(pdev, "failed to allocate bar0 region\n");
		return -ENOMEM;
	}

	for (i = 0; i < LIBETH_MMIO_REGION_MAX_NUM; i++) {
		if (!hw->mem_regions[i].addr)
			break;
	}
	if (i == LIBETH_MMIO_REGION_MAX_NUM)
		return -ENOMEM;

	hw->mem_regions[i].addr = va;
	hw->mem_regions[i].start_offset = offset;
	hw->mem_regions[i].size = size;
	hw->num_regions++;

	return 0;
}
EXPORT_SYMBOL(libeth_map_bar_region);
