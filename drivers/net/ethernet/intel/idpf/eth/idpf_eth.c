// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf_eth.h"
#include "idpf_netdev.h"

/* Forward declaration */
static void idpf_eth_device_post_init_task(struct work_struct *work);

/**
 * idpf_eth_statistics_task - Delayed task to get statistics over mailbox
 * @work: work_struct handle to eth adapter data
 */
void idpf_eth_statistics_task(struct work_struct *work)
{
	struct idpf_eth_adapter *adapter;
	struct idpf_vport *vport;

	adapter = container_of(work, struct idpf_eth_adapter, stats_task.work);
	vport = adapter->vport;
	if (vport && !test_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags))
		idpf_send_get_stats_msg(vport);

	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10000));
}

/**
 * idpf_eth_devlink_port_register - Create a devlink port for this adapter
 * @adapter: Idpf private data structure
 *
 * Create and register a devlink_port for ethernet adapter.
 * This function has to be called under devl_lock.
 *
 * Return: zero on success or an error code on failure.
 */
static int idpf_eth_devlink_port_register(struct idpf_eth_adapter *adapter)
{
	struct idpf_eth_idc_dev_info *dev_info;
	struct devlink_port_attrs attrs = {};
	struct devlink *devlink;
	struct device *dev;
	int err;

	dev_info = adapter->dev_info;
	dev = idpf_adapter_to_adev_dev(adapter);

	devlink = priv_to_devlink(adapter);
	attrs.flavour = DEVLINK_PORT_FLAVOUR_VIRTUAL;
	devlink_port_attrs_set(&adapter->devl_port, &attrs);

	err = devl_port_register(devlink, &adapter->devl_port,
				 dev_info->idx);
	if (err) {
		dev_err(dev, "Failed to create devlink port error %d\n", err);
		return err;
	}

	return 0;
}

/**
 * idpf_eth_devlink_alloc_adapter - Allocate devlink and return adapter
 * structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
static
struct idpf_eth_adapter *idpf_eth_devlink_alloc_adapter(struct device *dev)
{
	static struct devlink_ops idpf_devlink_ops = {};
	struct devlink *devlink;

	devlink = devlink_alloc(&idpf_devlink_ops,
				sizeof(struct idpf_eth_adapter), dev);
	if (!devlink)
		return NULL;

	return devlink_priv(devlink);
}

/**
 * idpf_eth_adapter_alloc - Allocate ethernet adapter struct
 * @dev: Device struct
 */
static struct idpf_eth_adapter *idpf_eth_adapter_alloc(struct device *dev)
{
	struct idpf_eth_adapter *adapter;

	adapter = idpf_eth_devlink_alloc_adapter(dev);
	if (!adapter)
		return NULL;

	adapter->post_init_wq = alloc_workqueue("%s-%s-pinit", 0, 0,
						dev_driver_string(dev),
						dev_name(dev));
	if (!adapter->post_init_wq) {
		dev_err(dev, "Failed to allocate post init workqueue\n");
		kfree(adapter);
		return NULL;
	}

	adapter->stats_wq = alloc_workqueue("%s-%s-stats", 0, 0,
					    dev_driver_string(dev),
					    dev_name(dev));
	if (!adapter->stats_wq) {
		dev_err(dev, "Failed to allocate workqueue\n");
		kfree(adapter);
		goto err_stats_wq;
	}

	INIT_DELAYED_WORK(&adapter->post_init_task,
			  idpf_eth_device_post_init_task);
	INIT_DELAYED_WORK(&adapter->stats_task, idpf_eth_statistics_task);
	mutex_init(&adapter->vport_ctrl_lock);

	return adapter;

err_stats_wq:
	destroy_workqueue(adapter->post_init_wq);
	kfree(adapter);
	return NULL;
}

/**
 * idpf_eth_device_post_init - Delayed ethernet post initialization
 * @adapter: Ethernet private data struct
 */
static void idpf_eth_device_post_init(struct idpf_eth_adapter *adapter)
{
	struct idpf_vport_config *vport_config;

	vport_config = adapter->vport_config;
	/* Vport/Netdev is ready for initialization */
	if (adapter->netdev &&
	    !test_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags)) {
		register_netdev(adapter->netdev);
		set_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags);
	}

	/* Mark the ethernet driver initialize completion */
	set_bit(IDPF_ETH_INIT_COMPLETE, adapter->flags);

	/* Start the statistics task now */
	queue_delayed_work(adapter->stats_wq, &adapter->stats_task, 0);
}

/**
 * idpf_eth_device_post_init_task - Delayed ethernet post initialization task
 * @work: work_struct handle to ethernet adapter data
 */
static void idpf_eth_device_post_init_task(struct work_struct *work)
{
	struct idpf_eth_adapter *adapter;

	adapter = container_of(work, struct idpf_eth_adapter,
			       post_init_task.work);

	/* Continue to schedule work if some probe pre-init(s) are pending */
	if (!adapter->start_post_init) {
		queue_delayed_work(adapter->post_init_wq,
				   &adapter->post_init_task,
				   msecs_to_jiffies(1));
		return;
	}

	/* Ready to finish the post init now */
	idpf_eth_device_post_init(adapter);
}

/**
 * idpf_eth_device_pre_init - Ethernet device pre-initialization routine
 * @adapter: Ethernet private data struct
 */
static int idpf_eth_device_pre_init(struct idpf_eth_adapter *adapter)
{
	struct idpf_vport_config *vport_config;
	struct idpf_eth_idc_dev_info *dev_info;
	struct idpf_netdev_priv *np;
	struct idpf_vport *vport;
	struct device *dev;
	int err;

	dev_info = adapter->dev_info;
	dev = idpf_adapter_to_adev_dev(adapter);
	adapter->req_tx_splitq = true;
	adapter->req_rx_splitq = true;
	err = idpf_send_create_vport_msg(adapter, &dev_info->caps.q_info);
	if (err)
		goto unwind_vports;

	vport = idpf_vport_alloc(adapter, &dev_info->caps.q_info);
	if (!vport) {
		err = -EFAULT;
		dev_err(dev, "failed to allocate vport: %d\n",	err);
		goto unwind_vports;
	}

	vport_config = adapter->vport_config;
	init_waitqueue_head(&vport->sw_marker_wq);
	spin_lock_init(&vport_config->mac_filter_list_lock);
	INIT_LIST_HEAD(&vport_config->user_config.mac_filter_list);

	err = idpf_check_supported_desc_ids(vport);
	if (err) {
		dev_err(dev, "failed to get required descriptor ids\n");
		goto cfg_netdev_err;
	}

	if (idpf_cfg_netdev(vport))
		goto cfg_netdev_err;

	err = idpf_send_get_rx_ptype_msg(vport);
	if (err)
		goto handle_err;

	/* Once state is put into DOWN, driver is ready for dev_open */
	np = netdev_priv(vport->netdev);
	np->state = __IDPF_VPORT_DOWN;
	if (test_and_clear_bit(IDPF_VPORT_UP_REQUESTED, vport_config->flags))
		idpf_vport_open(vport, true);

	return 0;

handle_err:
	idpf_decfg_netdev(vport);
cfg_netdev_err:
	idpf_vport_rel(vport);
	adapter->vport = NULL;
unwind_vports:
	if (adapter->vport)
		idpf_vport_dealloc(adapter->vport, false);
	return err;
}

/**
 * idpf_eth_probe - Probe ethernet device
 * @adev: Structure related to auxiliary ethernet device
 * @id: auxiliary device id
 */
static int idpf_eth_probe(struct auxiliary_device *adev,
			  const struct auxiliary_device_id *id)
{
	struct idpf_eth_idc_auxiliary_dev *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct device *dev;
	int err;

	eth_dev = container_of(adev, struct idpf_eth_idc_auxiliary_dev, adev);
	adapter = dev_get_drvdata(&adev->dev);
	dev = &adev->dev;
	if (!adapter) {
		adapter = idpf_eth_adapter_alloc(dev);
		if (!adapter)
			return -ENOMEM;

		/* Initialize dev_info */
		adapter->dev_info = &eth_dev->eth_info;
		adapter->req_tx_splitq = true;
		adapter->req_rx_splitq = true;
		dev_set_drvdata(&adev->dev, adapter);

		/* Devlink register */
		devl_register(priv_to_devlink(adapter));

		/* Devlink port register */
		devl_lock(priv_to_devlink(adapter));
		idpf_eth_devlink_port_register(adapter);
		devl_unlock(priv_to_devlink(adapter));

		/* setup msglvl */
		adapter->msg_enable = netif_msg_init(-1, IDPF_AVAIL_NETIF_M);
	}

	/* Save Eth device info */
	adapter->dev_info = &eth_dev->eth_info;
	adapter->start_post_init = false;

	/* Device's pre-initialization */
	err = idpf_eth_device_pre_init(adapter);

	/* Scheduling work for device's post-initialization */
	queue_delayed_work(adapter->post_init_wq, &adapter->post_init_task,
			   msecs_to_jiffies(2));
	return err;
}

/**
 * idpf_eth_remove - removes ethernet device
 * @adev: Structure related to auxiliary ethernet device
 */
static void idpf_eth_remove(struct auxiliary_device *adev)
{
	struct idpf_eth_adapter *adapter;
	struct idpf_eth_idc_event event;
	struct net_device *netdev;
	struct device *dev;

	adapter = dev_get_drvdata(&adev->dev);
	if (!adapter)
		return;

	dev = idpf_adapter_to_adev_dev(adapter);
	if (!test_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags)) {
		/* Notify lower layer of asynchronous eth removal */
		event.event_code = IDPF_ETH_IDC_EVENT_ETH_REMOVE_NOTIFY;
		idpf_eth_idc(adapter).event_send(adapter->dev_info, &event);

		set_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags);
	}

	idpf_eth_device_deinit(adapter);

	/* Cancel any pending task(s) */
	cancel_delayed_work_sync(&adapter->post_init_task);
	cancel_delayed_work_sync(&adapter->stats_task);

	if (adapter->netdev) {
		SET_NETDEV_DEVLINK_PORT(netdev, NULL);
		netdev = adapter->netdev;
		if (netdev->reg_state != NETREG_UNINITIALIZED)
			unregister_netdev(netdev);

		mutex_lock(&adapter->vport_ctrl_lock);
		free_netdev(netdev);
		adapter->netdev = NULL;
		mutex_unlock(&adapter->vport_ctrl_lock);
	}

	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
	kfree(adapter->vport);
	adapter->vport = NULL;

	destroy_workqueue(adapter->post_init_wq);
	destroy_workqueue(adapter->stats_wq);
	mutex_destroy(&adapter->vport_ctrl_lock);

	dev_err(dev, "Device removed");
	dev_set_drvdata(&adev->dev, NULL);
	devl_port_unregister(&adapter->devl_port);
	devl_unregister(priv_to_devlink(adapter));
	devlink_free(priv_to_devlink(adapter));
}

/**
 * idpf_eth_shutdown - shutdown ethernet device
 * @adev: Structure related to auxiliary ethernet device
 */
static void idpf_eth_shutdown(struct auxiliary_device *adev)
{
	struct idpf_eth_adapter *adapter;
	struct idpf_eth_idc_event event;

	adapter = dev_get_drvdata(&adev->dev);
	if (!adapter)
		return;

	if (!test_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags)) {
		/* Notify lower layer of asynchronous eth removal */
		event.event_code = IDPF_ETH_IDC_EVENT_ETH_REMOVE_NOTIFY;
		idpf_eth_idc(adapter).event_send(adapter->dev_info, &event);

		set_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags);
	}
}

/**
 * idpf_eth_event_handler - Ethernet device event handler to proess events
 * @dev_info: Device information
 * @event: Event info
 */
static void idpf_eth_event_handler(struct idpf_eth_idc_dev_info *dev_info,
				   struct idpf_eth_idc_event *event)
{
	struct idpf_eth_idc_auxiliary_dev *eth_dev;
	struct idpf_eth_adapter *adapter;

	eth_dev = container_of(dev_info, struct idpf_eth_idc_auxiliary_dev,
			       eth_info);
	adapter = dev_get_drvdata(&eth_dev->adev.dev);
	if (!adapter)
		return;

	switch (event->event_code) {
	case IDPF_ETH_IDC_EVENT_RESET_INITIATED:
		if (!test_bit(IDPF_ETH_INIT_COMPLETE, adapter->flags))
			return;

		mutex_lock(&adapter->vport_ctrl_lock);
		set_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags);
		/* Avoid TX hangs on reset */
		if (adapter->netdev)
			idpf_netdev_stop(adapter->netdev);
		idpf_set_vport_state(adapter);
		mutex_unlock(&adapter->vport_ctrl_lock);
		idpf_eth_device_deinit(adapter);
		break;

	case IDPF_ETH_IDC_EVENT_RESET_COMPLETE:
		mutex_lock(&adapter->vport_ctrl_lock);
		clear_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags);
		mutex_unlock(&adapter->vport_ctrl_lock);

		if (test_bit(IDPF_ETH_INIT_COMPLETE, adapter->flags)) {
			struct idpf_eth_idc_dev_info *eth_dev_info;
			struct idpf_eth_idc_auxiliary_dev *adev;

			eth_dev_info = adapter->dev_info;
			adev = container_of(eth_dev_info,
					    struct idpf_eth_idc_auxiliary_dev,
					    eth_info);
			idpf_eth_probe(&adev->adev, NULL);
		}
		break;

	case IDPF_ETH_IDC_EVENT_LINK_CHANGE:
		idpf_handle_event_link(adapter, event->event_data);
		break;

	case IDPF_ETH_IDC_EVENT_POST_INIT:
		adapter->start_post_init = true;
		break;

	default:
		break;
	}
}

/**
 * idpf_eth_device_deinit - Ethernet device deinit routine
 * @adapter: Ethernet Driver specific private structure
 *
 * Ethernet device initialization logic
 */
void idpf_eth_device_deinit(struct idpf_eth_adapter *adapter)
{
	/* Acquire lock */
	mutex_lock(&adapter->vport_ctrl_lock);
	cancel_delayed_work_sync(&adapter->post_init_task);
	cancel_delayed_work_sync(&adapter->stats_task);
	/* Release lock before making system call */
	mutex_unlock(&adapter->vport_ctrl_lock);

	idpf_netdev_stop(adapter->netdev);

	/* Re-acquire lock */
	mutex_lock(&adapter->vport_ctrl_lock);

	if (adapter->vport)
		idpf_vport_dealloc(adapter->vport, true);

	/* Release lock */
	mutex_unlock(&adapter->vport_ctrl_lock);
}

static const struct auxiliary_device_id idpf_eth_id_table[] = {
	{ .name = "idpf.eth", },
	{ },
};

MODULE_DEVICE_TABLE(auxiliary, idpf_eth_id_table);

static struct idpf_eth_idc_auxiliary_driver idpf_eth_driver = {
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
 * @void: void
 */
struct idpf_eth_idc_auxiliary_driver *idpf_eth_get_driver(void)
{
	return &idpf_eth_driver;
}
