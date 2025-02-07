// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2025 Intel Corporation */

#include "idpf.h"
#include "idpf_virtchnl.h"
#include "idpf_aux_idc.h"

/**
 * idpf_aux_init_device_params - Initialize auxiliary device params
 * @adapter: IDPF main private structure
 * @eth_dev: Auxiliary (Ethernet) dev info
 */
static void
idpf_aux_init_device_params(struct idpf_adapter *adapter,
			    struct idpf_auxiliary_device *eth_dev)
{
	/* crc info */
	eth_dev->aux_info.caps.crc_enable = true;

	/* Queue Info */
	eth_dev->aux_info.caps.q_info.max_rxq =
		le16_to_cpu(adapter->caps.max_rx_q);
	eth_dev->aux_info.caps.q_info.max_txq =
		le16_to_cpu(adapter->caps.max_tx_q);
	eth_dev->aux_info.caps.q_info.max_bufq =
		le16_to_cpu(adapter->caps.max_rx_bufq);
	eth_dev->aux_info.caps.q_info.max_complq =
		le16_to_cpu(adapter->caps.max_tx_complq);

	/* Caps */
	eth_dev->aux_info.caps.csum_caps = adapter->caps.csum_caps;
	eth_dev->aux_info.caps.seg_caps = adapter->caps.seg_caps;
	eth_dev->aux_info.caps.hsplit_caps =
		adapter->caps.hsplit_caps;
	eth_dev->aux_info.caps.rsc_caps = adapter->caps.rsc_caps;
	eth_dev->aux_info.caps.rss_caps = adapter->caps.rss_caps;
	eth_dev->aux_info.caps.other_caps = adapter->caps.other_caps;
	eth_dev->aux_info.caps.max_tx_hdr_size = adapter->caps.max_tx_hdr_size;
	eth_dev->aux_info.caps.max_sg_bufs_per_tx_pkt =
		adapter->caps.max_sg_bufs_per_tx_pkt;
	eth_dev->aux_info.caps.min_sso_packet_len =
		adapter->caps.min_sso_packet_len;
}

/**
 * idpf_aux_release - Release IDPF aux device associated with auxiliary device
 * @device: pointer to the device
 */
static void idpf_aux_release(struct device *device)
{
	struct auxiliary_device *adev = to_auxiliary_dev(device);
	struct idpf_auxiliary_device *aux_dev;

	aux_dev = container_of(adev, struct idpf_auxiliary_device,
			       adev);
	kfree(aux_dev);
}

/**
 * idpf_aux_alloc_dev - allocate one auxiliary device
 * @adapter: IDPF main private structure
 * @index: auxiliary device index
 * @vport_type: Vport type
 *
 * Returns allocated structure
 */
static struct idpf_auxiliary_device *
idpf_aux_alloc_dev(struct idpf_adapter *adapter, unsigned int index,
		   enum idpf_vport_type vport_type)
{
	struct idpf_auxiliary_device *aux_dev;
	struct idpf_vport_max_q *max_q;
	u16 err;

	aux_dev = kzalloc(sizeof(*aux_dev), GFP_KERNEL);
	if (!aux_dev)
		return NULL;

	aux_dev->adev.id = index;
	aux_dev->adev.name = "eth";
	aux_dev->adev.dev.release = idpf_aux_release;
	aux_dev->adev.dev.parent = &adapter->pdev->dev;

	aux_dev->aux_info.aux_shared = &adapter->aux_shared;
	aux_dev->aux_info.vport_type = vport_type;
	aux_dev->aux_info.id = index;
	aux_dev->aux_info.vport_id = -1;
	max_q = &aux_dev->aux_info.caps.q_info;
	err = idpf_vport_alloc_max_qs(adapter, max_q,
				      vport_type == IDPF_DEFAULT_VPORT);
	if (err) {
		kfree(aux_dev);
		return NULL;
	}

	return aux_dev;
}

/**
 * idpf_aux_free_dev - free one auxiliary device
 * @adapter: IDPF main private structure
 * @aux_dev: the auxiliary device to be freed
 */
static void idpf_aux_free_dev(struct idpf_adapter *adapter,
			      struct idpf_auxiliary_device *aux_dev)
{
	struct idpf_vport_max_q *max_q;

	max_q = &aux_dev->aux_info.caps.q_info;
	idpf_vport_dealloc_max_qs(adapter, max_q);
	kfree(aux_dev);
}

/**
 * idpf_aux_allocate_devices - Allocate, initialize and auxiliary devices
 * @adapter: IDPF main private structure
 *
 * Returns 0 in case of success, negative error number otherwise.
 */
int idpf_aux_add_devices(struct idpf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct idpf_auxiliary_device *aux_dev;
	unsigned int i;
	int err;

	adapter->adevs =
		kzalloc((adapter->max_vports *
			 sizeof(struct idpf_auxiliary_device *)),
			GFP_KERNEL);
	if (!adapter->adevs)
		return -ENOMEM;

	for (i = 0; i < idpf_get_default_vports(adapter); i++) {
		aux_dev = idpf_aux_alloc_dev(adapter, i, IDPF_DEFAULT_VPORT);
		if (!aux_dev)
			return -ENOMEM;

		/* Initialize the auxiliary device parameters */
		idpf_aux_init_device_params(adapter, aux_dev);

		/* Add the devices to the auxiliary bus */
		err = auxiliary_device_init(&aux_dev->adev);
		if (err) {
			dev_err(dev, "Auxiliary dev %u init failed: (%d)\n",
				i, err);
			idpf_aux_free_dev(adapter, aux_dev);
			return err;
		}

		err = auxiliary_device_add(&aux_dev->adev);
		if (err) {
			dev_err(dev, "Auxiliary dev %u add failed: (%d)\n",
				i, err);
			auxiliary_device_uninit(&aux_dev->adev);
			idpf_aux_free_dev(adapter, aux_dev);
			return err;
		}

		adapter->adevs[i] = aux_dev;
	}

	return 0;
}

/**
 * idpf_aux_del_devices - Remove all auxiliary devices
 * @adapter: IDPF main private structure
 */
void idpf_aux_del_devices(struct idpf_adapter *adapter)
{
	struct idpf_auxiliary_device *aux_dev;
	unsigned int i;

	for (i = 0; i < idpf_get_default_vports(adapter); i++) {
		aux_dev = adapter->adevs[i];
		if (aux_dev) {
			auxiliary_device_delete(&aux_dev->adev);
			auxiliary_device_uninit(&aux_dev->adev);
			idpf_aux_free_dev(adapter, adapter->adevs[i]);
		}
	}

	kfree(adapter->adevs);
}

/**
 * idpf_aux_dispatch_event - Send event to auxiliary devices)
 * @adapter: IDPF main private structure
 * @code: IDC event code
 * @dev_info: Auxiliary device info, NULL to dispatch to all devices
 * @data: Event-specific data
 *
 * Returns number of auxiliary devices the event was dispatched to.
 */
int idpf_aux_dispatch_event(struct idpf_adapter *adapter,
			    enum idpf_aux_idc_event_code code,
			    struct idpf_aux_dev_info *dev_info,
			    void *data)
{
	struct idpf_auxiliary_driver *aux_drv;
	struct idpf_aux_idc_event event;
	int i, devs = 0;

	if (!adapter->adevs)
		return devs;

	aux_drv = idpf_eth_get_driver();

	event.event_code = code;
	event.event_data = data;
	if (!dev_info) {
		for (i = 0; i < idpf_get_default_vports(adapter); ++i) {
			if (!adapter->adevs[i])
				continue;

			dev_info = &adapter->adevs[i]->aux_info;
			aux_drv->event_handler(dev_info, &event);
			devs++;
		}
	} else {
		if (event.event_code == IDPF_AUX_IDC_EVENT_LINK_CHANGE) {
			aux_drv->event_handler(dev_info, &event);
			devs++;
		}
	}

	return devs;
}

/**
 * idpf_aux_recv_event - Recieve an event from auxiliary device
 * @adapter: Auxiliary device info
 * @event: IDC event
 */
static void idpf_aux_recv_event(struct idpf_aux_dev_info *dev_info,
				struct idpf_aux_idc_event *event)
{
	struct idpf_auxiliary_device *aux_dev;
	struct idpf_adapter *adapter;
	struct device *dev;
	unsigned int id;

	aux_dev = container_of(dev_info, struct idpf_auxiliary_device,
			       aux_info);
	adapter = container_of(dev_info->aux_shared, struct idpf_adapter,
			       aux_shared);
	dev = idpf_aux_to_dev(aux_dev);

	switch (event->event_code) {
	case IDPF_AUX_IDC_EVENT_REQ_HARD_RESET:
		if (!idpf_is_reset_in_prog(adapter)) {
			set_bit(IDPF_HR_FUNC_RESET, adapter->flags);
			queue_delayed_work(adapter->vc_event_wq,
					   &adapter->vc_event_task,
					   msecs_to_jiffies(10));
		}
		break;

	case IDPF_AUX_IDC_EVENT_REMOVE_NOTIFY:
		auxiliary_device_delete(&aux_dev->adev);
		auxiliary_device_uninit(&aux_dev->adev);
		id = aux_dev->aux_info.id;
		idpf_aux_free_dev(adapter, adapter->adevs[id]);
		break;

	default:
		dev_err(dev, "Unknwon auxiliary event: %u\n",
			event->event_code);
		break;
	}
}

/**
 * idpf_aux_recv_virtchnl - Pass on a virtchnl msg on behalf of auxiliary dev
 * @adapter: Auxiliary device info
 * @params: Virtchnl2 parameters
 */
static ssize_t idpf_aux_recv_virtchnl(struct idpf_aux_dev_info *dev_info,
				      struct idpf_vc_xn_params *params)
{
	struct idpf_adapter *adapter;

	adapter = container_of(dev_info->aux_shared, struct idpf_adapter,
			       aux_shared);
	return idpf_vc_xn_exec(adapter, params);
}

/**
 * idpf_aux_init_shared - Initialize the auxiliary shared info
 * @adapter: IDPF main private structure
 */
void idpf_aux_init_shared(struct idpf_adapter *adapter)
{
	struct idpf_idc_ops *idc_ops;

	adapter->aux_shared.hw_addr = adapter->hw.hw_addr;

	idc_ops = &adapter->aux_shared.idc_ops;
	idc_ops->event_send = idpf_aux_recv_event;
	idc_ops->virtchnl_send = idpf_aux_recv_virtchnl;
	idc_ops->intr_reg_init = adapter->dev_ops.reg_ops.intr_reg_init;
	idc_ops->intr_init_vec_idx = idpf_vport_intr_init_vec_idx;
	idc_ops->req_rel_vec_idx = idpf_req_rel_vector_indexes;
}

/**
 * idpf_aux_driver_register - Register auxiliary driver
 * @void: void
 *
 * Returns 0 on success, negative on failure
 */
int idpf_aux_driver_register(void)
{
	struct idpf_auxiliary_driver *eth_drv;

	eth_drv = idpf_eth_get_driver();
	return auxiliary_driver_register(&eth_drv->adrv);
}

/**
 * idpf_aux_driver_unregister - unregister auxiliary driver
 * @void: void
 */
void idpf_aux_driver_unregister(void)
{
	struct idpf_auxiliary_driver *eth_drv;

	eth_drv = idpf_eth_get_driver();
	auxiliary_driver_unregister(&eth_drv->adrv);
}

