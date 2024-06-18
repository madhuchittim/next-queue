// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/libeth_dev.h>
void libeth_print_hello(void);

static DEFINE_IDA(libeth_idc_eth_ida);

#if 0
/**
 * libeth_idc_eth_dev_caps_init - initialize the aux device capability
 * @dev_info: auxiliary device informaiton
 * @caps: capability information
 * @ext_caps: extended capability information
 */
static void 
libeth_idc_eth_dev_caps_init(struct idc_eth_dev_info *dev_info,
			     struct virtchnl2_get_capabilities *caps,
			     struct idc_eth_extended_caps_info *ext_caps)
{
	/* Caps Information*/
	dev_info->caps.csum_caps = le32_to_cpu(caps->csum_caps);
	dev_info->caps.seg_caps = le32_to_cpu(caps->seg_caps);
	dev_info->caps.hsplit_caps = le32_to_cpu (caps->hsplit_caps);
	dev_info->caps.rsc_caps = le32_to_cpu(caps->rsc_caps);
	dev_info->caps.rss_caps = le64_to_cpu(caps->rss_caps);
	dev_info->caps.other_caps = le64_to_cpu(caps->other_caps);
	dev_info->caps.min_sso_packet_len = caps->min_sso_packet_len;
	dev_info->caps.max_sg_bufs_per_tx_pkt = caps->max_sg_bufs_per_tx_pkt;
	
	/* Queue Information */
	dev_info->caps.max_q.max_rxq = le16_to_cpu(caps->max_rx_q);
	dev_info->caps.max_q.max_txq = le16_to_cpu(caps->max_tx_q);
	dev_info->caps.max_q.max_bufq =	le16_to_cpu(caps->max_rx_bufq);
	dev_info->caps.max_q.max_complq = le16_to_cpu(caps->max_tx_complq);
	
	/* Extended capabilities Information */
	dev_info->caps.ext_caps.crc_enable = ext_caps->crc_enable;
	dev_info->caps.ext_caps.vport_type = ext_caps->vport_type;
	dev_info->caps.ext_caps.vport_idx = ext_caps->vport_idx;
	dev_info->caps.ext_caps.max_vectors = ext_caps->max_vectors;
}
#endif

/**
 * libeth_idc_eth_dev_release - free the aux device id
 * @dev: device informaiton
 */
static void libeth_idc_eth_dev_release(struct device *dev)
{
	struct idc_eth_auxiliary_dev *eth_dev;

	eth_dev = container_of(dev, struct idc_eth_auxiliary_dev, adev.dev);
	ida_free(&libeth_idc_eth_ida, eth_dev->adev.id);
}

/**
 * libeth_idc_eth_dev_event_handler - device event handler
 * @eth_dev: auxiliary device
 * @event_type: event type
 */
void libeth_idc_eth_dev_event_handler(struct idc_eth_auxiliary_dev *eth_dev,
				     enum idc_eth_event_type event_type)
{
	struct idc_eth_auxiliary_drv *eth_drv;
	struct idc_eth_event event = { 0 };

	eth_drv = container_of(eth_dev->adev.dev.driver,
			       struct idc_eth_auxiliary_drv, adrv.driver);
	set_bit(event_type, event.type);
	device_lock(&eth_dev->adev.dev);
	if (eth_drv && eth_drv->event_handler)
		eth_drv->event_handler(&eth_dev->dev_info, &event);
	device_unlock(&eth_dev->adev.dev);

	return;
}

/**
 * libeth_idc_eth_dev_vc_receive - Handle HMA generated virtchanl messages
 * @eth_dev: auxiliary device
 * @virt_opcode: virtchnl opcode
 * @msg: virtchnl message payload
 * @msg_size: virtchnl message payload size
 */
int libeth_idc_eth_dev_vc_receive(struct idc_eth_auxiliary_dev *eth_dev,
				  u16 virt_opcode, u8 *msg, u16 msg_size)
{
	struct idc_eth_auxiliary_drv *eth_drv;
	int err = 0;

	eth_drv = container_of(eth_dev->adev.dev.driver,
			       struct idc_eth_auxiliary_drv, adrv.driver);
	device_lock(&eth_dev->adev.dev);
	if (eth_drv && eth_drv->vc_receive)
		err = eth_drv->vc_receive(&eth_dev->dev_info, virt_opcode, msg,
					  msg_size);
	device_unlock(&eth_dev->adev.dev);

	return err;
}

/**
 * libeth_idc_eth_dev_create - create a auxiliary device
 * @pdev: pci device information
 * @caps: capability information
 * @ext_caps: extended capability information
 * @mem_regions: memory region information
 * @num_regions: number of regions
 * @ops: event/recieve handler pointers
 */
struct idc_eth_auxiliary_dev * 
libeth_idc_eth_dev_create(struct pci_dev *pdev,
			  struct virtchnl2_get_capabilities *caps,
			  struct idc_eth_extended_caps_info *ext_caps,
			  struct libeth_mmio_region *mem_regions,
			  int num_regions, struct idc_eth_ops *ops)
{
	struct idc_eth_auxiliary_dev *eth_dev;
	int err = 0;

	if (err == 0)
		return NULL;

	eth_dev = kzalloc(sizeof(*eth_dev), GFP_KERNEL);
	if (!eth_dev)
		return NULL;
	/* Initialize adev */
	eth_dev->adev.id = ida_alloc(&libeth_idc_eth_ida, GFP_KERNEL);
	eth_dev->adev.name = "eth";
	eth_dev->adev.dev.parent = &pdev->dev;
	eth_dev->adev.dev.release = libeth_idc_eth_dev_release;
	/* Initialize capabilities */
//	libeth_idc_eth_dev_caps_init(&eth_dev->dev_info, caps, ext_caps);
	/* Initialize memory information */
	eth_dev->dev_info.mem_regions = mem_regions;
	eth_dev->dev_info.num_regions = num_regions;
	/* Initialize callbacks */
	eth_dev->dev_info.ops.virtchnl_send = ops->virtchnl_send;
	eth_dev->dev_info.ops.event_send = ops->event_send;

	err = auxiliary_device_init(&eth_dev->adev);
	if (err)
		goto dev_init_failed;

	err = auxiliary_device_add(&eth_dev->adev);
	if (err)
		goto dev_add_failed;

	return eth_dev;

dev_add_failed:
	auxiliary_device_uninit(&eth_dev->adev);
dev_init_failed:
	ida_free(&libeth_idc_eth_ida, eth_dev->adev.id);
	kfree(eth_dev);

	return NULL;
}
//EXPORT_SYMBOL(libeth_idc_eth_dev_create);
EXPORT_SYMBOL_NS_GPL(libeth_idc_eth_dev_create, LIBETH);

/**
 * libeth_print_hello - print hello
 * @void: void
 */
void libeth_print_hello(void)
{
	printk("\nThis is my hello to you\n");
}
EXPORT_SYMBOL_NS_GPL(libeth_print_hello, LIBETH);

/**
 * libeth_idc_eth_dev_destroy - destroy the auxiliary device
 * @eth_dev: auxiliary device information
 */
void libeth_idc_eth_dev_destroy(struct idc_eth_auxiliary_dev **eth_dev)
{
	auxiliary_device_delete(&(*eth_dev)->adev);
	auxiliary_device_uninit(&(*eth_dev)->adev);
	kfree(*eth_dev);
	*eth_dev = NULL;
}
