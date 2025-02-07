// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2025 Intel Corporation */

#include "idpf_eth.h"
#include "idpf_aux_idc.h"
#include "idpf_virtchnl.h"

/**
 * idpf_eth_device_deinit - Ethernet device deinit routine
 * @adapter: Ethernet Driver specific private structure
 *
 * Ethernet device initialization
 */
static void idpf_eth_device_deinit(struct idpf_eth_adapter *adapter)
{
	cancel_delayed_work_sync(&adapter->stats_task);

	idpf_vport_stop(adapter->vport);
	if (adapter->vport)
		idpf_vport_dealloc(adapter->vport);
}

/**
 * idpf_eth_adapter_alloc - Allocate and init Ethernet adapter struct
 * @dev: Auxiliary device struct
 *
 * Returns: pointer to allocated adapter
 */
static struct idpf_eth_adapter *
idpf_eth_adapter_alloc(struct idpf_auxiliary_device *eth_dev)
{
	struct device *dev = idpf_aux_to_dev(eth_dev);
	struct idpf_eth_adapter *adapter;

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return NULL;

	adapter->wq = alloc_workqueue("%s-%s-wq", 0, 0,
				      dev_driver_string(dev),
				      dev_name(dev));
	if (!adapter->wq) {
		kfree(adapter);
		return NULL;
	}

	INIT_DELAYED_WORK(&adapter->stats_task, idpf_statistics_task);
	mutex_init(&adapter->ctrl_lock);

	return adapter;
}

/**
 * idpf_eth_adapter_free - Free the Ethernet adapter struct
 * @dev: Auxiliary device struct
 *
 */
static void idpf_eth_adapter_free(struct idpf_eth_adapter *adapter)
{
	kfree(adapter->vport_params_reqd);
	kfree(adapter->vport_params_recvd);
	destroy_workqueue(adapter->wq);
	mutex_destroy(&adapter->ctrl_lock);
	kfree(adapter);
}

/**
 * idpf_eth_probe - Probe ethernet device
 * @adev: Structure related to auxiliary ethernet device
 * @id: auxiliary device id
 *
 * Called from init and reset paths.
 *
 * Returns: O if probe succeeds, or negative error otherwise
 */
static int idpf_eth_probe(struct auxiliary_device *adev,
			  const struct auxiliary_device_id *id)
{
	struct idpf_auxiliary_device *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct idpf_netdev_priv *np;
	struct idpf_vport *vport;
	struct device *dev;
	int err;

	eth_dev = container_of(adev, struct idpf_auxiliary_device, adev);
	adapter = dev_get_drvdata(&adev->dev);
	dev = idpf_aux_to_dev(eth_dev);

	if (!adapter) {
		adapter = idpf_eth_adapter_alloc(eth_dev);
		if (!adapter)
			return -ENOMEM;

		adapter->dev_info = &eth_dev->aux_info;
		adapter->req_tx_splitq = true;
		adapter->req_rx_splitq = true;
		dev_set_drvdata(dev, adapter);

		/* setup debug level */
		adapter->msg_enable = netif_msg_init(-1, IDPF_AVAIL_NETIF_M);
	}

	err = idpf_send_create_vport_msg(adapter);
	if (err)
		return err;

	vport = idpf_vport_alloc(adapter);
	if (!vport)
		return -ENOMEM;

	err = idpf_check_supported_desc_ids(vport);
	if (err) {
		dev_err(dev, "failed to get required descriptor ids (%d)\n",
			err);
		goto dealloc_vport;
	}

	err = idpf_cfg_netdev(vport);
	if (err)
		goto dealloc_vport;

	err = idpf_send_get_rx_ptype_msg(vport);
	if (err)
		goto dealloc_vport;

	/* Once state is put into DOWN, driver is ready for dev_open */
	np = netdev_priv(vport->netdev);
	np->state = __IDPF_VPORT_DOWN;
	if (test_and_clear_bit(IDPF_VPORT_UP_REQUESTED,
			       adapter->vport_config.flags))
		err = idpf_vport_open(vport);

	if (!err)
		return 0;

dealloc_vport:
	idpf_vport_dealloc(vport);
	return err;
}

/**
 * idpf_eth_remove - removes ethernet device
 * @adev: Structure related to auxiliary ethernet device
 */
static void idpf_eth_remove(struct auxiliary_device *adev)
{
	struct idpf_auxiliary_device *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct idpf_aux_idc_event event;
	struct device *dev = &adev->dev;
	struct net_device *netdev;

	eth_dev = container_of(adev, struct idpf_auxiliary_device, adev);
	adapter = dev_get_drvdata(&adev->dev);
	if (!adapter)
		return;

	if (test_and_set_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags))
		return;

	mutex_lock(&adapter->ctrl_lock);
	if (adapter->netdev) {
		netdev = adapter->netdev;
		if (netdev->reg_state != NETREG_UNINITIALIZED)
			unregister_netdev(netdev);

		free_netdev(netdev);
		adapter->netdev = NULL;
	}

	idpf_vport_dealloc(adapter->vport);
	idpf_eth_device_deinit(adapter);
	mutex_unlock(&adapter->ctrl_lock);

	idpf_eth_adapter_free(adapter);
	event.event_code = IDPF_AUX_IDC_EVENT_REMOVE_NOTIFY;
	idpf_aux_event_send(eth_dev, &event);

	dev_err(dev, "Device removed");
	dev_set_drvdata(&adev->dev, NULL);
}

/**
 * idpf_eth_shutdown - shutdown ethernet device
 * @adev: Structure related to auxiliary ethernet device
 */
static void idpf_eth_shutdown(struct auxiliary_device *adev)
{
	struct idpf_auxiliary_device *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct idpf_aux_idc_event event;

	eth_dev = container_of(adev, struct idpf_auxiliary_device, adev);

	adapter = dev_get_drvdata(&adev->dev);
	if (!adapter)
		return;

	if (!test_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags)) {
		event.event_code = IDPF_AUX_IDC_EVENT_REMOVE_NOTIFY;
		idpf_aux_event_send(eth_dev, &event);

		set_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags);
	}
}

/**
 * idpf_eth_event_handler - receive events from main driver
 * @dev_info: Ethernet device information
 * @event: Event info
 */
static int idpf_eth_event_handler(struct idpf_aux_dev_info *dev_info,
				  struct idpf_aux_idc_event *event)
{
	struct idpf_auxiliary_device *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct idpf_netdev_priv *np;

	eth_dev = container_of(dev_info, struct idpf_auxiliary_device,
			       aux_info);
	adapter = dev_get_drvdata(&eth_dev->adev.dev);

	/* This could happen if probe fails */
	if (!adapter)
		return 0;

	switch (event->event_code) {
	case IDPF_AUX_IDC_EVENT_RESET_INITIATED:
		if (test_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags))
			return -EBUSY;

		mutex_lock(&adapter->ctrl_lock);
		set_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags);

		/* Avoid TX hangs on reset */
		if (adapter->netdev) {
			np = netdev_priv(adapter->netdev);
			if (np->state == __IDPF_VPORT_UP)
				set_bit(IDPF_VPORT_UP_REQUESTED,
					adapter->vport_config.flags);
		}
		idpf_eth_device_deinit(adapter);
		mutex_unlock(&adapter->ctrl_lock);
		break;

	case IDPF_AUX_IDC_EVENT_RESET_COMPLETE:
		struct idpf_aux_dev_info *eth_dev_info;
		struct idpf_auxiliary_device *adev;

		eth_dev_info = adapter->dev_info;
		adev = container_of(eth_dev_info,
				    struct idpf_auxiliary_device,
				    aux_info);
		idpf_eth_probe(&adev->adev, NULL);
		clear_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags);
		break;

	case IDPF_AUX_IDC_EVENT_LINK_CHANGE:
		idpf_handle_event_link(adapter, event->event_data);
		break;

	default:
		break;
	}

	return 0;
}

static const struct auxiliary_device_id idpf_eth_id_table[] = {
	{ .name = "idpf.eth", },
	{ },
};

MODULE_DEVICE_TABLE(auxiliary, idpf_eth_id_table);

static struct idpf_auxiliary_driver idpf_eth_driver = {
	.adrv = {
		.name = "eth",
		.probe = idpf_eth_probe,
		.remove = idpf_eth_remove,
		.shutdown = idpf_eth_shutdown,
		.id_table = idpf_eth_id_table
	},
	.event_handler = idpf_eth_event_handler
};

/**
 * idpf_eth_get_driver - returns ethernet device driver structure
 */
struct idpf_auxiliary_driver* idpf_eth_get_driver(void)
{
	return &idpf_eth_driver;
}

