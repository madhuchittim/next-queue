/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */
#ifndef _IDC_ETH_H_
#define _IDC_ETH_H_

#include <linux/auxiliary_bus.h>
#include "libeth_virtchnl.h"

/**
 * struct idc_eth_q_info - Queue limits
 * @max_rxq: Maximum number of RX queues supported
 * @max_txq: Maixmum number of TX queues supported
 * @max_bufq: In splitq, maximum number of buffer queues supported
 * @max_complq: In splitq, maximum number of completion queues supported
 */
struct idc_eth_q_info {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/** struct idc_eth_extended_caps_info - Extended capabilities
 * crc_enable: crc status
 * vport_type: type of the vport
 * vport_idx: index used while registering netdev
 * max_vectors: maximum vectors
 */
struct idc_eth_extended_caps_info {
	bool crc_enable;
	enum virtchnl2_vport_type vport_type;
	u16 vport_idx;
	u16 max_vectors;
};

/**
 * struct idc_eth_dev_caps - Capabilities info
 * @csum_caps: See enum virtchnl2_cap_txrx_csum
 * @seg_caps: See enum virtchnl2_cap_seg
 * @hsplit_caps: See enum virtchnl2_cap_rx_hsplit_at
 * @rsc_caps: See enum virtchnl2_cap_rsc
 * @rss_caps: See enum virtchnl2_cap_rss
 * @other_caps: See enum virtchnl2_cap_other
 * @max_tx_hdr_size: Max header length hardware can parse/checksum, in bytes.
 * @max_sg_bufs_per_tx_pkt: Max number of scatter gather buffers that can be
 *			    sent per transmit packet without needing to be
 *			    linearized.
 * @min_sso_packet_len: Min packet length supported by device for single
 *	segment offload
 * @max_q: Max queue information
 * @ext_caps: extended capabilities
 */
struct idc_eth_dev_caps {
	__le32 csum_caps;
	__le32 seg_caps;
	__le32 hsplit_caps;
	__le32 rsc_caps;
	__le64 rss_caps;
	__le64 other_caps;
	__le16 max_tx_hdr_size;
	u8 max_sg_bufs_per_tx_pkt;
	u8 min_sso_packet_len;
	struct idc_eth_q_info max_q;
	struct idc_eth_extended_caps_info ext_caps;
};

/**
 * @vport_id: vport identifier
 * @netdev: registered netdevice
*/
struct idc_eth_vport_info {
	u16 vport_id;
	struct net_device *netdev;
};

/**
 * @IDC_ETH_EVENT_VIRTCHNL: response received with virtchnl2_event
 * @IDC_ETH_EVENT_BEFORE_RESET: before reset event
 * @IDC_ETH_EVENT_AFTER_RESET: after reset event
 * @IDC_ETH_EVENT_REQ_HARD_RESET: request hard reset event
 * @IDC_ETH_EVENT_VPORT_CREATED: vport created event
 * @IDC_ETH_EVENT_BEFORE_MTU_CHANGE: before mtu change event
 * @IDC_ETH_EVENT_AFTER_MTU_CHANGE: after mtu change event
 * @IDC_ETH_EVENT_BEFORE_TC_CHANGE: before tc change event
 * @IDC_ETH_EVENT_AFTER_TC_CHANGE: after tc change event
 */
enum idc_eth_event_type {
	/* Following events are from main driver to aux/eth driver */
	IDC_ETH_EVENT_BEFORE_RESET,
	IDC_ETH_EVENT_AFTER_RESET,

	/* Following requests are from auxiliary eth driver to main driver */
	IDC_ETH_EVENT_REQ_HARD_RESET,
	IDC_ETH_EVENT_VPORT_CREATED,
	IDC_ETH_EVENT_BEFORE_MTU_CHANGE,
	IDC_ETH_EVENT_AFTER_MTU_CHANGE,
	IDC_ETH_EVENT_BEFORE_TC_CHANGE,
	IDC_ETH_EVENT_AFTER_TC_CHANGE,
	IDC_ETH_EVENT_NBITS
};

/**
 * struct idc_eth_event - ethernet idc events
 * @type: Event code
 * @reg: Event data
 */
struct idc_eth_event {
	DECLARE_BITMAP(type, IDC_ETH_EVENT_NBITS);
	u32 reg;
};

struct idc_eth_dev_info;
/**
 * struct idc_eth_ops - Ethernet driver ops to pci driver (aux to pci)
 * @event_send: Sends ethernet events from aux to pci driver
 * @virtchnl_send: Sends Virtchnl messages from aux to pci driver
 */
struct idc_eth_ops {
	void (*event_send)(struct idc_eth_dev_info *dev_info,
			   struct idc_eth_event *event);
	size_t (*virtchnl_send)(struct idc_eth_dev_info *dev_info,
				struct libeth_virtchnl_msg_param *virt_data);
};

/**
 * struct idc_eth_dev_info - Ethernet driver's device information struct
 * @num_regions: number of memory mapped regions
 * @mem_regions: memory mapped bar regions
 * @eth_ops: Ethernet auxiliary device operations
 * @eth_caps: Ethernet auxiliary device capabilities
 */
struct idc_eth_dev_info {
	u16 num_regions;
	struct libeth_mmio_region *mem_regions;
	struct idc_eth_ops ops;
	struct idc_eth_dev_caps caps;
};

/**
 * struct idc_eth_auxiliary_dev - Represents auxiliary device
 * @adev: Auxiliary device
 * @dev_info: Ethernet private data struct
 */
struct idc_eth_auxiliary_dev {
	struct auxiliary_device adev;
	struct idc_eth_dev_info dev_info;
};

/**
 * struct idc_eth_auxiliary_drv - Ethernet driver info struct (pci to aux)
 * @adrv: Auxiliary driver
 * @event_handler: Ethernet driver's event handler
 * @vc_receive: Ethernet driver's receive handler
 */
struct idc_eth_auxiliary_drv {
	struct auxiliary_driver adrv;
	void (*event_handler)(struct idc_eth_dev_info *dev_info,
			      struct idc_eth_event *event);
	int (*vc_receive)(struct idc_eth_dev_info *dev_info, u16 virt_opcode,
			  u8 *msg, u16 msg_size);
};

#endif /* !_IDC_ETH_H_ */
