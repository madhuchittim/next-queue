/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_ETH_IDC_H_
#define _IDPF_ETH_IDC_H_

#include <linux/auxiliary_bus.h>
#include "idpf_eth_common.h"

enum idpf_eth_idc_event_code {
	/* Following events are from main driver to aux/eth driver */
	IDPF_ETH_IDC_EVENT_LINK_CHANGE,
	IDPF_ETH_IDC_EVENT_RESET_INITIATED,
	IDPF_ETH_IDC_EVENT_RESET_COMPLETE,
	IDPF_ETH_IDC_EVENT_POST_INIT,

	/* Following requests are from auxiliary eth driver to main driver */
	IDPF_ETH_IDC_EVENT_REQ_HARD_RESET,
	IDPF_ETH_IDC_EVENT_ETH_REMOVE_NOTIFY,
};

/**
 * struct idpf_eth_idc_auxiliary_dev_caps - Capabilities info
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
 * @q_info: Max queue information
 * @crc_enable: Enable CRC insertion offload
 */
struct idpf_eth_idc_auxiliary_dev_caps {
	__le32 csum_caps;
	__le32 seg_caps;
	__le32 hsplit_caps;
	__le32 rsc_caps;
	__le64 rss_caps;
	__le64 other_caps;
	__le16 max_tx_hdr_size;
	u8 max_sg_bufs_per_tx_pkt;
	u8 min_sso_packet_len;
	struct idpf_max_q q_info;
	bool crc_enable;
};

/**
 * struct idpf_eth_idc_event - ethernet idc events
 * @event_data: Event data
 * @event_code: Event code
 */
struct idpf_eth_idc_event {
	void *event_data;
	enum idpf_eth_idc_event_code event_code;
};

struct idpf_eth_idc_dev_info;
/**
 * struct idpf_eth_idc_ops - Ethernet driver ops to main driver
 * @event_send: Sends ethernet event to main driver
 * @virtchnl_send: Sends Virtchnl messages call to main driver
 * @intr_reg_init: Initialize interrupt registers call to main driver
 * @intr_init_vec_idx: Initialize the vector indexes call to main driver
 * @req_rel_vec_idx: Release vector indexes call to main driver
 */
struct idpf_eth_idc_ops {
	void (*event_send)(struct idpf_eth_idc_dev_info *dev_info,
			   struct idpf_eth_idc_event *event);
	size_t (*virtchnl_send)(struct idpf_eth_idc_dev_info *dev_info,
				struct idpf_vc_xn_params *params);
	int (*intr_reg_init)(struct idpf_eth_idc_dev_info *dev_info,
			     u16 num_vecs, struct idpf_q_vector *q_vectors,
			      u16 *q_vector_idxs);
	int (*intr_init_vec_idx)(struct idpf_eth_idc_dev_info *dev_info,
				 u16 num_vecs,
				 struct idpf_q_vector *q_vectors,
				 u16 *q_vector_idxs);
	int (*req_rel_vec_idx)(struct idpf_eth_idc_dev_info *dev_info,
			       u16 *num_vectors,
			       struct idpf_vector_info *vec_info,
			       struct msix_entry *msix_table);
};

/**
 * struct idpf_eth_shared - Common Device data struct shared with eth
 * @pdev: PCI device struct given on probe
 * @hw_addr: Hardware address for use by Ethernet driver
 */
struct idpf_eth_shared {
	struct idpf_eth_idc_ops eth_idc_ops;
	void __iomem *hw_addr;
};

/**
 * struct idpf_eth_idc_dev_info - Ethernet driver's device information struct
 * @eth_shared: Ethernet shared data struct
 * @vport_type: Vport type
 * @caps: Auxiliary device capabilities
 * @vport_id: Vport ID of device
 * @idx: Index number of auxiliary device
 */
struct idpf_eth_idc_dev_info {
	struct idpf_eth_shared *eth_shared;
	enum idpf_vport_type vport_type;
	struct idpf_eth_idc_auxiliary_dev_caps caps;
	u32 vport_id;
	u16 idx;
};

/**
 * struct idpf_eth_idc_auxiliary_dev - Represents auxiliary device
 * @adev: Auxiliary device
 * @eth_info: Ethernet private data struct
 */
struct idpf_eth_idc_auxiliary_dev {
	struct auxiliary_device adev;
	struct idpf_eth_idc_dev_info eth_info;
};

/**
 * struct idpf_eth_idc_auxiliary_driver - Ethernet driver info struct
 * @signature: Signature value
 * @adrv: Auxiliary driver
 * @event_handler: Ethernet driver's event handler
 */
struct idpf_eth_idc_auxiliary_driver {
	unsigned long signature;
	struct auxiliary_driver adrv;
	void (*event_handler)(struct idpf_eth_idc_dev_info *dev_info,
			      struct idpf_eth_idc_event *event);
};

#endif /* !_IDPF_ETH_IDC_H_ */
