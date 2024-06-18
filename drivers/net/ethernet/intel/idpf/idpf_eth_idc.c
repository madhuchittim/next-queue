// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"
#if 0
#include "net/libeth/libeth_eth_idc.h"
#include "net/libeth/libeth_dev.h"
#else
void libeth_print_hello(void);
#endif

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

	adapter = container_of(dev_info->eth_shared, struct idpf_adapter,
			       eth_shared);
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

	adapter = container_of(dev_info->eth_shared, struct idpf_adapter,
			       eth_shared);
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

	adapter = container_of(dev_info->eth_shared, struct idpf_adapter,
			       eth_shared);
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

	adapter = container_of(dev_info->eth_shared, struct idpf_adapter,
			       eth_shared);
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

	adapter = container_of(dev_info->eth_shared, struct idpf_adapter,
			       eth_shared);
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
 * idpf_eth_idc_vid_to_dev_info - Translate v_id to eth dev_info
 * @adapter: Idpf private structure
 * @v_id: vport id to translate
 *
 * Returns dev_info matching v_id, NULL if not found.
 */
static struct idpf_eth_idc_dev_info *
idpf_eth_idc_vid_to_dev_info(struct idpf_adapter *adapter,
			     u32 v_id)
{
	struct idpf_eth_idc_dev_info *eth_info;
	int i;

	for (i = 0; i < adapter->default_vports; ++i) {
		if (!adapter->adevs[i])
			continue;
		eth_info = &adapter->adevs[i]->eth_info;
		if (v_id == eth_info->vport_id)
			return eth_info;
	}

	return NULL;
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
	struct virtchnl2_event *v2e;
	u32 vport_id;
	int i;

	if (!adapter->adevs)
		return;

	event.event_code = event_code;
	event.event_data = event_data;
	eth_idc_drv = idpf_eth_idc_get_driver();
	switch (event_type) {
	case IDPF_ETH_IDC_EVENT_ALL_VPORTS:
		for (i = 0; i < adapter->default_vports; ++i) {
			if (!adapter->adevs[i])
				continue;

			eth_info = &adapter->adevs[i]->eth_info;
			eth_idc_drv->event_handler(eth_info, &event);
		}
		break;

	case IDPF_ETH_IDC_EVENT_SINGLE_VPORT:
		switch (event.event_code) {
		case IDPF_ETH_IDC_EVENT_LINK_CHANGE:
			v2e = (struct virtchnl2_event *)event.event_data;
			/* vport_id indexes the dev_info instance */
			vport_id = le32_to_cpu(v2e->vport_id);
			eth_info =  idpf_eth_idc_vid_to_dev_info(adapter,
								 vport_id);
			if (eth_info)
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
 * @dev: pointer to device to free allocated memory
 */
static
void idpf_eth_idc_device_free(struct device *dev)
{
	struct idpf_eth_idc_auxiliary_dev *eth_adev;

	eth_adev = container_of(dev, struct idpf_eth_idc_auxiliary_dev,
				adev.dev);
	ida_free(&idpf_eth_idc_ida, eth_adev->adev.id);
}

/**
 * idpf_eth_idc_driver_register - Register ethernet auxiliary driver
 * @void: void
 *
 * Returns 0 on success, negative on failure
 */
int idpf_eth_idc_driver_register(void)
{
	struct idpf_eth_idc_auxiliary_driver *eth_idc_drv;

	eth_idc_drv = idpf_eth_idc_get_driver();
	return auxiliary_driver_register(&eth_idc_drv->adrv);
}

/**
 * idpf_eth_idc_driver_unregister - unregister ethernet driver
 * @void: void
 */
void idpf_eth_idc_driver_unregister(void)
{
	struct idpf_eth_idc_auxiliary_driver *eth_idc_drv;

	eth_idc_drv = idpf_eth_idc_get_driver();
	auxiliary_driver_unregister(&eth_idc_drv->adrv);
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
	/* crc info */
	eth_dev->eth_info.caps.crc_enable = adapter->crc_enable;

	/* Queue Info */
	eth_dev->eth_info.caps.q_info.max_rxq =
		le16_to_cpu(adapter->caps.max_rx_q);
	eth_dev->eth_info.caps.q_info.max_txq =
		le16_to_cpu(adapter->caps.max_tx_q);
	eth_dev->eth_info.caps.q_info.max_bufq =
		le16_to_cpu(adapter->caps.max_rx_bufq);
	eth_dev->eth_info.caps.q_info.max_complq =
		le16_to_cpu(adapter->caps.max_tx_complq);

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
 * @index: adev index
 * @vport_type: Vport type
 *
 * Returns allocated structure
 */
static struct idpf_eth_idc_auxiliary_dev *
idpf_eth_idc_device_alloc(struct idpf_adapter *adapter,
			  u16 index,
			  enum idpf_vport_type vport_type)
{
	struct idpf_eth_idc_auxiliary_dev *new_eth_dev;
	struct idpf_eth_idc_dev_info *dev_info;
	u16 err;

	if (index >= adapter->default_vports)
		return NULL;

	if (!adapter->adevs[index])
		adapter->adevs[index] =
			kzalloc(sizeof(struct idpf_eth_idc_auxiliary_dev),
				GFP_KERNEL);

	new_eth_dev = adapter->adevs[index];
	if (!new_eth_dev)
		goto alloc_exit;

	new_eth_dev->adev.id = ida_alloc(&idpf_eth_idc_ida, GFP_KERNEL);
	new_eth_dev->eth_info.eth_shared = &adapter->eth_shared;
	new_eth_dev->eth_info.idx = index;
	new_eth_dev->adev.name = "eth";
	new_eth_dev->adev.dev.release = idpf_eth_idc_device_free;
	new_eth_dev->adev.dev.parent = &adapter->pdev->dev;

	/* Set vport type */
	new_eth_dev->eth_info.vport_type = vport_type;

	dev_info = &new_eth_dev->eth_info;
	err = idpf_alloc_max_qs(adapter, &dev_info->caps.q_info,
				vport_type);
	if (err) {
		kfree(adapter->adevs[index]);
		adapter->adevs[index] = NULL;
		new_eth_dev = NULL;
	}

	return new_eth_dev;

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
	struct device *dev = &adapter->pdev->dev;
	int err;
	u16 i;

//############### EXPERIMENT START ############################
#if 0
	struct idc_eth_auxiliary_dev *eth_aux_dev;
	struct virtchnl2_get_capabilities caps;
	//struct idc_eth_extended_caps_info ext_caps;
	//struct libeth_mmio_region *mem_regions = NULL;
	int num_regions = 0;
	//struct idc_eth_ops ops;

	eth_aux_dev = libeth_idc_eth_dev_create(adapter->pdev, &caps, NULL,
						NULL, num_regions, NULL);
	if (!eth_aux_dev)
		printk("libeth_idc_eth_dev_create : [eth_aux_dev = %p]",
			eth_aux_dev);
#else
	libeth_print_hello();
#endif
//############### EXPERIMENT END ##############################

	/* Check if device is already initialized */
	if (adapter->adevs)
		return;

	/* This is the case of initial probe */
	adapter->adevs =
		kzalloc((adapter->max_vports *
			 sizeof(struct idpf_eth_idc_auxiliary_dev *)),
			GFP_KERNEL);
	if (!adapter->adevs)
		return;

	for (i = 0; i < adapter->default_vports; ++i) {
		eth_dev = idpf_eth_idc_device_alloc(adapter, i,
						    IDPF_DEFAULT_VPORT);
		if (!eth_dev)
			return;

		/* Initialize ethernet parameter(s) */
		idpf_eth_idc_init_device_params(adapter, eth_dev);

		err = auxiliary_device_init(&eth_dev->adev);
		if (err) {
			dev_err(dev, "Auxiliary dev ID 0x%x init failed 0x%x\n",
				i, err);
		} else {
			err = auxiliary_device_add(&eth_dev->adev);
			if (err)
				continue;
		}
	}
}

/**
 * idpf_eth_idc_device_deinit - Deinitialize ethernet IDC
 * @adapter: Idpf private structure
 */
void idpf_eth_idc_device_deinit(struct idpf_adapter *adapter)
{
	u16 i;

	if (!adapter->adevs)
		return;

	for (i = 0; i < adapter->default_vports; ++i) {
		struct idpf_eth_idc_auxiliary_dev *eth_adev;

		eth_adev = adapter->adevs[i];
		auxiliary_device_delete(&eth_adev->adev);
		auxiliary_device_uninit(&eth_adev->adev);

		/* Release all max queues allocated to the pool */
		idpf_dealloc_max_qs(adapter, &eth_adev->eth_info.caps.q_info);

		kfree(adapter->adevs[i]);
		adapter->adevs[i] = NULL;
	}

	kfree(adapter->adevs);
	adapter->adevs = NULL;
}
