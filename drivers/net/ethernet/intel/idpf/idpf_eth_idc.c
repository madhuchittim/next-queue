// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"

static DEFINE_IDA(idpf_eth_idc_ida);

/**
 * idpf_eth_idc_event_send - Called by an Auxiliary Driver to send event
 * to Main Driver
 * @dev_info: Ethernet device information struct
 * @event: Event information
 *
 * Ethernet driver sends the event to main driver.
 */
static void idpf_eth_idc_event_send(struct idpf_eth_idc_dev_info *dev_info,
				    struct idpf_eth_idc_event *event)
{
	struct idpf_adapter *adapter;

	adapter = idpf_dev_info_to_adapter(dev_info);
	idpf_recv_eth_event(adapter, event);
}

/**
 * idpf_eth_idc_virtchnl_send - Called by an Auxiliary Driver
 * @dev_info: Device information
 * @params: Virtchnl parameters
 */
static
size_t idpf_eth_idc_virtchnl_send(struct idpf_eth_idc_dev_info *dev_info,
				  struct idpf_vc_xn_params *params)
{
	struct idpf_adapter *adapter;

	adapter = idpf_dev_info_to_adapter(dev_info);
	return idpf_vc_xn_exec(adapter, params);
}

/**
 * idpf_eth_idc_intr_reg_init - Called by an Auxiliary Driver
 * @dev_info: Device information
 * @num_vecs: Number of vectors
 * @q_vectors: Queue vectors info
 * @q_vector_idxs: Queue vectors index info
 */
static int idpf_eth_idc_intr_reg_init(struct idpf_eth_idc_dev_info *dev_info,
				      u16 num_vecs,
				      struct idpf_q_vector *q_vectors,
				      u16 *q_vector_idxs)
{
	struct idpf_adapter *adapter;

	adapter = idpf_dev_info_to_adapter(dev_info);
	return adapter->dev_ops.reg_ops.intr_reg_init(adapter, num_vecs,
						      q_vectors, q_vector_idxs);
}

/**
 * idpf_eth_idc_intr_init_vec_idx - Called by an Auxiliary Driver
 * @dev_info: Device information
 * @num_vecs: Number of vectors
 * @q_vectors: Queue vectors info
 * @q_vector_idxs: Queue vectors index info
 */
static
int idpf_eth_idc_intr_init_vec_idx(struct idpf_eth_idc_dev_info *dev_info,
				   u16 num_vecs,
				   struct idpf_q_vector *q_vectors,
				   u16 *q_vector_idxs)
{
	struct idpf_adapter *adapter;

	adapter = idpf_dev_info_to_adapter(dev_info);
	return idpf_intr_init_vec_idx(adapter, num_vecs,
				      q_vectors, q_vector_idxs);
}

/**
 * idpf_eth_idc_req_rel_vector_indexes - Called by an Auxiliary Driver
 * @dev_info: Device information
 * @num_vectors: Number of vectors
 * @vec_info: Vecor information
 * @msix_table: MSIX table
 */
static
int idpf_eth_idc_req_rel_vector_indexes(struct idpf_eth_idc_dev_info *dev_info,
					u16 *num_vectors,
					struct idpf_vector_info *vec_info,
					struct msix_entry *msix_table)
{
	struct idpf_adapter *adapter;

	adapter = idpf_dev_info_to_adapter(dev_info);
	return idpf_req_rel_vector_indexes(adapter, num_vectors, vec_info,
					   msix_table);
}

extern struct idpf_eth_idc_auxiliary_driver *idpf_eth_get_driver(void);
/**
 * idpf_eth_idc_get_driver - returns eth driver ops
 * @void: void
 */
static struct idpf_eth_idc_auxiliary_driver *idpf_eth_idc_get_driver(void)
{
	return idpf_eth_get_driver();
}

/**
 * idpf_eth_idc_dispatch_event - Called by Main Driver to send event
 * @adapter: Idpf adapter private structure
 * @event_type: Event type for all or single ports
 * @event_code: Event code
 * @event_data: Event data related to event code
 */
void idpf_eth_idc_dispatch_event(struct idpf_adapter *adapter,
				 enum idpf_eth_idc_event_type event_type,
				 enum idpf_eth_idc_event_code event_code,
				 void *event_data)
{
	struct idpf_eth_idc_auxiliary_driver *eth_idc_drv;
	struct idpf_eth_idc_dev_info *eth_info;
	struct idpf_eth_idc_event event;

	if (!adapter->adevs || !adapter->adevs[0])
		return;

	event.event_code = event_code;
	event.event_data = event_data;
	eth_idc_drv = idpf_eth_idc_get_driver();
	eth_info = &adapter->adevs[0]->eth_info;
	if (!eth_info)
		return;

	switch (event_type) {
	case IDPF_ETH_IDC_EVENT_ALL_VPORTS:
		eth_idc_drv->event_handler(eth_info, &event);
		break;

	case IDPF_ETH_IDC_EVENT_SINGLE_VPORT:
		switch (event.event_code) {
		case IDPF_ETH_IDC_EVENT_LINK_CHANGE:
			eth_idc_drv->event_handler(eth_info, &event);
			break;

		default:
			break;
		}
		break;

	default:
		break;
	}
}

/**
 * idpf_eth_idc_init_shared - Initialize ethernet shared struct
 * @eth_shared: Ethernet and main apdater shared struct
 *
 * Returns 0 on success, negative on failure
 */
int idpf_eth_idc_init_shared(struct idpf_eth_shared *eth_shared)
{
	/* IDC ops */
	eth_shared->eth_idc_ops.event_send = idpf_eth_idc_event_send;
	eth_shared->eth_idc_ops.virtchnl_send = idpf_eth_idc_virtchnl_send;
	eth_shared->eth_idc_ops.intr_reg_init = idpf_eth_idc_intr_reg_init;
	eth_shared->eth_idc_ops.intr_init_vec_idx =
		idpf_eth_idc_intr_init_vec_idx;
	eth_shared->eth_idc_ops.req_rel_vec_idx =
		idpf_eth_idc_req_rel_vector_indexes;

	return 0;
}

/**
 * idpf_eth_idc_deinit_shared - De-Initialize ethernet shared struct
 * @eth_shared: Ethernet and main apdater shared struct
 */
void idpf_eth_idc_deinit_shared(struct idpf_eth_shared *eth_shared)
{
	eth_shared->hw_addr = NULL;

	eth_shared->eth_idc_ops.event_send = NULL;
	eth_shared->eth_idc_ops.virtchnl_send = NULL;
	eth_shared->eth_idc_ops.intr_reg_init = NULL;
	eth_shared->eth_idc_ops.intr_init_vec_idx = NULL;
	eth_shared->eth_idc_ops.req_rel_vec_idx = NULL;
}

/**
 * idpf_eth_idc_device_free - function to be mapped to aux dev's release op
 * @eth_adev: pointer to device to free allocated memory
 */
static
void idpf_eth_idc_device_free(struct idpf_eth_idc_auxiliary_dev *eth_adev)
{
	struct idpf_adapter *adapter;
	u16 idx, i;

	adapter = (struct idpf_adapter *)eth_adev->eth_info.idpf_context;
	ida_free(&idpf_eth_idc_ida, eth_adev->adev.id);
	idx = eth_adev->eth_info.idx;

	/* Release all max queues allocated to the pool */
	for (i = 0; i < adapter->default_vports; i++)
		idpf_dealloc_max_qs(adapter,
				    &eth_adev->eth_info.caps.q_info[i]);

	kfree(adapter->adevs[idx]);
	adapter->adevs[idx] = NULL;
}

/**
 * idpf_eth_idc_driver_unregister - unregister ethernet driver
 * @adapter: Idpf private structure
 */
void idpf_eth_idc_driver_unregister(struct idpf_adapter *adapter)
{
	idpf_eth_unregister(&adapter->adevs[0]->adev);
	idpf_eth_idc_device_free(adapter->adevs[0]);
	kfree(adapter->adevs);
	adapter->adevs = NULL;
}

/**
 * idpf_eth_idc_init_device_params - Initialize device params
 * @adapter: Idpf private structure
 * @eth_dev: Ethernet dev info
 */
static void
idpf_eth_idc_init_device_params(struct idpf_adapter *adapter,
				struct idpf_eth_idc_auxiliary_dev *eth_dev)
{
	u16 i;

	/* crc info */
	eth_dev->eth_info.caps.crc_enable = adapter->crc_enable;
	eth_dev->eth_info.default_vports = adapter->default_vports;

	/* Queue Info */
	for (i = 0; i < adapter->default_vports; i++) {
		eth_dev->eth_info.caps.q_info[i].max_rxq =
			le16_to_cpu(adapter->caps.max_rx_q);
		eth_dev->eth_info.caps.q_info[i].max_txq =
			le16_to_cpu(adapter->caps.max_tx_q);
		eth_dev->eth_info.caps.q_info[i].max_bufq =
			le16_to_cpu(adapter->caps.max_rx_bufq);
		eth_dev->eth_info.caps.q_info[i].max_complq =
			le16_to_cpu(adapter->caps.max_tx_complq);
	}

	/* Caps */
	eth_dev->eth_info.caps.csum_caps = adapter->caps.csum_caps;
	eth_dev->eth_info.caps.seg_caps = adapter->caps.seg_caps;
	eth_dev->eth_info.caps.hsplit_caps =
		adapter->caps.hsplit_caps;
	eth_dev->eth_info.caps.rsc_caps = adapter->caps.rsc_caps;
	eth_dev->eth_info.caps.rss_caps = adapter->caps.rss_caps;
	eth_dev->eth_info.caps.other_caps = adapter->caps.other_caps;
	eth_dev->eth_info.caps.min_sso_packet_len =
		adapter->caps.min_sso_packet_len;
	eth_dev->eth_info.caps.max_sg_bufs_per_tx_pkt =
		adapter->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_eth_idc_device_alloc - allocate auxiliary device
 * @adapter: Idpf private structure
 * @vport_type: Vport type
 *
 * Returns allocated structure
 */
static struct idpf_eth_idc_auxiliary_dev *
idpf_eth_idc_device_alloc(struct idpf_adapter *adapter,
			  enum idpf_vport_type vport_type)
{
	struct idpf_eth_idc_auxiliary_dev *new_eth_dev;
	struct idpf_eth_idc_dev_info *dev_info;
	struct idpf_max_q *q_info;
	u16 i, j;
	int err;

	if (!adapter->adevs[0]) {
		adapter->adevs[0] =
			kzalloc(sizeof(struct idpf_eth_idc_auxiliary_dev),
				GFP_KERNEL);
		new_eth_dev = adapter->adevs[0];
		if (!new_eth_dev)
			goto alloc_exit;

		new_eth_dev->eth_info.caps.q_info =
			kzalloc((adapter->max_vports *
				 sizeof(struct idpf_max_q)), GFP_KERNEL);
		if (!new_eth_dev->eth_info.caps.q_info) {
			kfree(adapter->adevs[0]);
			goto alloc_exit;
		}

		new_eth_dev->adev.id = ida_alloc(&idpf_eth_idc_ida, GFP_KERNEL);
		new_eth_dev->eth_info.eth_shared = &adapter->eth_shared;
		new_eth_dev->eth_info.idpf_context = (void *)adapter;
		new_eth_dev->eth_info.eth_context = NULL;
		new_eth_dev->eth_info.idx = 0;
		/* Set vport type */
		new_eth_dev->eth_info.vport_type = vport_type;

		dev_info = &new_eth_dev->eth_info;
		/* Allocate queue(s) */
		for (i = 0; i < adapter->default_vports; i++) {
			q_info = &dev_info->caps.q_info[i];
			err = idpf_alloc_max_qs(adapter, q_info, vport_type);
			if (!err)
				continue;

			/* free resources */
			for (j = 0; j < i; j++) {
				q_info = &dev_info->caps.q_info[j];
				idpf_dealloc_max_qs(adapter, q_info);
			}
			kfree(adapter->adevs[0]);
			adapter->adevs[0] = NULL;
			new_eth_dev = NULL;
		}

		return new_eth_dev;
	}

alloc_exit:
	return NULL;
}

/**
 * idpf_eth_idc_device_init - Initialize ethernet device to start probe
 * @adapter: Idpf private structure
 */
void idpf_eth_idc_device_init(struct idpf_adapter *adapter)
{
	struct idpf_eth_idc_auxiliary_dev *eth_dev;

	/* This is the case of initial probe */
	adapter->adevs =
		kzalloc(sizeof(struct idpf_eth_idc_auxiliary_dev *),
			GFP_KERNEL);
	if (!adapter->adevs)
		return;

	eth_dev = idpf_eth_idc_device_alloc(adapter, IDPF_DEFAULT_VPORT);
	if (!eth_dev)
		return;

	eth_dev->adev.name = "eth";
	eth_dev->adev.dev.parent = &adapter->pdev->dev;

	/* Initialize ethernet parameter(s) */
	idpf_eth_idc_init_device_params(adapter, eth_dev);

	/* Direct eth device add */
	idpf_eth_device_add(&adapter->adevs[0]->adev, NULL);
}
