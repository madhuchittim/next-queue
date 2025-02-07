/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2025 Intel Corporation */

#ifndef _IDPF_AUX_IDC_H_
#define _IDPF_AUX_IDC_H_

#include <linux/auxiliary_bus.h>

#include "idpf_virtchnl.h"

struct idpf_aux_dev_info;
struct idpf_vc_xn_params;
struct idpf_q_vector;
struct idpf_vector_info;

enum idpf_aux_idc_event_code {
	/* Following events are from main driver to aux driver */
	IDPF_AUX_IDC_EVENT_LINK_CHANGE,
	IDPF_AUX_IDC_EVENT_RESET_INITIATED,
	IDPF_AUX_IDC_EVENT_RESET_COMPLETE,

	/* Following requests are from auxiliary driver to main driver */
	IDPF_AUX_IDC_EVENT_REQ_HARD_RESET,
	IDPF_AUX_IDC_EVENT_REMOVE_NOTIFY,
};

/**
 * struct idpf_vport_max_q - Queue limits
 * @max_rxq: Maximum number of RX queues supported
 * @max_txq: Maixmum number of TX queues supported
 * @max_bufq: In splitq, maximum number of buffer queues supported
 * @max_complq: In splitq, maximum number of completion queues supported
 */
struct idpf_vport_max_q {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/**
 * struct idpf_eth_aux_dev_caps - Ethernet capabilities info
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
struct idpf_eth_aux_dev_caps {
	__le32 csum_caps;
	__le32 seg_caps;
	__le32 hsplit_caps;
	__le32 rsc_caps;
	__le64 rss_caps;
	__le64 other_caps;
	__le16 max_tx_hdr_size;
	u8 max_sg_bufs_per_tx_pkt;
	u8 min_sso_packet_len;
	struct idpf_vport_max_q q_info;
	bool crc_enable;
};

/**
 * struct idpf_aux_idc_event - Main/auxiliary drivers idc events
 * @event_data: Event data
 * @event_code: Event code
 */
struct idpf_aux_idc_event {
	void *event_data;
	enum idpf_aux_idc_event_code event_code;
};

/**
 * struct idpf_idc_ops - IDPF IDC main callback ops
 * @event_send: Sends event to main driver
 * @virtchnl_send: Sends Virtchnl messages to main driver
 * @intr_reg_init: Initialize interrupt registers
 * @intr_init_vec_idx: Initialize the vector indexes
 * @req_rel_vec_idx: Release vector indexes
 */
struct idpf_idc_ops {
	void (*event_send)(struct idpf_aux_dev_info *dev_info,
			   struct idpf_aux_idc_event *event);
	ssize_t (*virtchnl_send)(struct idpf_aux_dev_info *dev_info,
				 struct idpf_vc_xn_params *params);
	int (*intr_reg_init)(struct idpf_aux_dev_info *dev_info,
			     u16 num_vecs,
			     struct idpf_q_vector *q_vectors,
			     u16 *q_vector_idxs);
	int (*intr_init_vec_idx)(struct idpf_aux_dev_info *dev_info,
				 u16 num_vecs,
				 struct idpf_q_vector *q_vectors,
				 u16 *q_vector_idxs);
	int (*req_rel_vec_idx)(struct idpf_aux_dev_info *dev_info,
			       u16 *num_vectors,
			       struct idpf_vector_info *vec_info,
			       struct msix_entry *msix_table);
};

/**
 * struct idpf_aux_shared - Common Device data struct shared with auxiliary
 * @idc_ops: Callbacks provided to auxiliary drivers
 * @hw_addr: Hardware address to be used by Auxiliary driver
 */
struct idpf_aux_shared {
	struct idpf_idc_ops idc_ops;
	void __iomem *hw_addr;
};

/**
 * enum idpf_vport_type
 * @IDPF_DEFAULT_VPORT: Default vport
 * @IDPF_DYNAMIC_VPORT: Dynamic vport
 */
enum idpf_vport_type {
	IDPF_DEFAULT_VPORT = 1,
	IDPF_DYNAMIC_VPORT
};

/**
 * struct idpf_aux_dev_info - Aux driver's device information struct
 * @aux_shared: auxiliary shared data struct
 * @vport_type: Vport type
 * @caps: Ethernet auxiliary device capabilities
 * @vport_id: ID of the vport assigned to the auxiliary device (-1 for none)
 * @id: Index number of auxiliary device
 */
struct idpf_aux_dev_info {
	struct idpf_aux_shared *aux_shared;
	struct idpf_eth_aux_dev_caps caps;
	enum idpf_vport_type vport_type;
	int vport_id;		/* Set by the auxiliary device */
	unsigned int id;
};

/**
 * struct idpf_auxiliary_device - IDPF auxiliary device info
 * @adev: Auxiliary device
 * @aux_info: Auxiliary private data struct
 */
struct idpf_auxiliary_device {
	struct auxiliary_device adev;
	struct idpf_aux_dev_info aux_info;
};

/**
 * struct idpf_auxiliary_driver - Auxiliary driver info struct
 * @adrv: Auxiliary driver
 * @event_handler: Auxiliary driver's event handler
 */
struct idpf_auxiliary_driver {
	struct auxiliary_driver adrv;
	int (*event_handler)(struct idpf_aux_dev_info *dev_info,
			     struct idpf_aux_idc_event *event);
};

/**
 * idpf_aux_to_dev - Get device structure
 * @aux_dev: IDPF auxiliary device
 *
 * Returns dev struct.
 */
static inline
struct device *idpf_aux_to_dev(struct idpf_auxiliary_device *aux_dev)
{
	return &aux_dev->adev.dev;
}

/**
 * idpf_aux_virtchnl_send - Send Virtchnl2 message to main driver
 * @dev_info: IDPF auxiliary device info
 * @params: Vitchnl2 parameters
 */
static inline
ssize_t idpf_aux_virtchnl_send(struct idpf_aux_dev_info *dev_info,
			       struct idpf_vc_xn_params *params)
{
	struct idpf_idc_ops *idc_ops = &dev_info->aux_shared->idc_ops;
	return idc_ops->virtchnl_send(dev_info, params);
}

/**
 * idpf_aux_event_send - Send an IDC event to main driver
 * @aux_dev: IDPF auxiliary device
 */
static inline
void idpf_aux_event_send(struct idpf_auxiliary_device *aux_dev,
			 struct idpf_aux_idc_event *event)
{
	struct idpf_idc_ops *idc_ops = &aux_dev->aux_info.aux_shared->idc_ops;
	idc_ops->event_send(&aux_dev->aux_info, event);
}

/**
 * idpf_eth_get_reg_addr - reg operations
 * @eth_shared: Ethernet shared information
 * @reg_offset: Register offset
 */
static inline
void __iomem *idpf_aux_get_reg_addr(struct idpf_auxiliary_device *aux_dev,
				    resource_size_t reg_offset)
{
	return (void __iomem *)
		aux_dev->aux_info.aux_shared->hw_addr + reg_offset;
}

int idpf_aux_add_devices(struct idpf_adapter *adapter);
void idpf_aux_del_devices(struct idpf_adapter *adapter);
void idpf_aux_init_shared(struct idpf_adapter *adapter);
void idpf_aux_dispatch_event(struct idpf_adapter *adapter,
			     enum idpf_aux_idc_event_code code,
			     struct idpf_aux_dev_info *dev_info,
			     void *data);
struct idpf_auxiliary_driver* idpf_eth_get_driver(void);
int idpf_aux_driver_register(void);
void idpf_aux_driver_unregister(void);
#endif /* !_IDPF_AUX_IDC_H_ */
