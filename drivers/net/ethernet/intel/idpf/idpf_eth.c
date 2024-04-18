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
 * idpf_eth_adapter_alloc - Allocate ethernet adapter struct
 * @dev: Device struct
 */
static struct idpf_eth_adapter *idpf_eth_adapter_alloc(struct device *dev)
{
	struct idpf_eth_adapter *adapter;

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
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
	dev = idpf_adapter_to_pdev_dev(adapter);
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
 * idpf_eth_device_add - Adds ethernet device
 * @adev: Structure related to ethernet device information
 * @id: auxiliary device id
 */
int idpf_eth_device_add(struct auxiliary_device *adev,
			const struct auxiliary_device_id *id)
{
	struct idpf_eth_idc_auxiliary_dev *eth_dev;
	struct idpf_eth_adapter *adapter;
	struct device *dev;
	int err;

	eth_dev = container_of(adev, struct idpf_eth_idc_auxiliary_dev, adev);
	adapter = eth_dev->eth_info.eth_context;
	dev = &adev->dev;
	if (!adapter) {
		adapter = idpf_eth_adapter_alloc(dev);
		if (!adapter)
			return -ENOMEM;

		/* Initialize dev_info */
		adapter->dev_info = &eth_dev->eth_info;
		adapter->dev_info->eth_context = adapter;
		adapter->req_tx_splitq = true;
		adapter->req_rx_splitq = true;

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
 * @adev: Structure related to ethernet device information
 */
static void idpf_eth_remove(struct auxiliary_device *adev)
{
	struct idpf_eth_idc_auxiliary_dev *dev_info;
	struct idpf_eth_adapter *adapter;
	struct net_device *netdev;

	dev_info = container_of(adev, struct idpf_eth_idc_auxiliary_dev, adev);
	adapter = dev_info->eth_info.eth_context;
	if (!adapter)
		return;

	if (adapter->netdev) {
		netdev = adapter->netdev;
		if (netdev) {
			if (netdev->reg_state != NETREG_UNINITIALIZED)
				unregister_netdev(netdev);
			free_netdev(netdev);
			adapter->netdev = NULL;
		}
	}

	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
	kfree(adapter->vport);
	adapter->vport = NULL;

	destroy_workqueue(adapter->post_init_wq);
	destroy_workqueue(adapter->stats_wq);
	mutex_destroy(&adapter->vport_ctrl_lock);

	dev_info->eth_info.eth_context = NULL;
	kfree(adapter);
}

/**
 * idpf_eth_event_handler - Ethernet device event handler to proess events
 * @dev_info: Device information
 * @event: Event info
 */
static void idpf_eth_event_handler(struct idpf_eth_idc_dev_info *dev_info,
				   struct idpf_eth_idc_event *event)
{
	struct idpf_eth_adapter *adapter;

	adapter = dev_info->eth_context;
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
			idpf_eth_device_add(&adev->adev, NULL);
		}
		break;

	case IDPF_ETH_IDC_EVENT_LINK_CHANGE:
		idpf_handle_event_link(adapter, event->event_data);
		break;

	case IDPF_ETH_IDC_EVENT_REMOVE:
		set_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags);
		idpf_eth_device_deinit(adapter);
		break;

	case IDPF_ETH_IDC_EVENT_POST_INIT:
		adapter->start_post_init = true;
		break;

	default:
		break;
	}
}

static struct idpf_eth_idc_auxiliary_driver idpf_eth_driver = {
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

/**
 * idpf_eth_unregister - unregister ethernet device
 * @adev: Ethernet auxiliary device
 */
void idpf_eth_unregister(struct auxiliary_device *adev)
{
	if (!adev)
		return;

	idpf_eth_remove(adev);
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

