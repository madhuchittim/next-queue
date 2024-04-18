// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf_eth.h"
#include "idpf_netdev.h"

/* Forward declaration */
static void idpf_eth_device_pre_init_task(struct work_struct *work);
static void idpf_eth_device_post_init_task(struct work_struct *work);

/**
 * idpf_eth_statistics_task - Delayed task to get statistics over mailbox
 * @work: work_struct handle to eth adapter data
 */
void idpf_eth_statistics_task(struct work_struct *work)
{
	struct idpf_eth_adapter *adapter;
	u16 default_vports;
	int i;

	adapter = container_of(work, struct idpf_eth_adapter, stats_task.work);
	default_vports = adapter->dev_info->default_vports;
	for (i = 0; i < default_vports; i++) {
		struct idpf_vport *vport = adapter->vports[i];

		if (vport && !test_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags))
			idpf_send_get_stats_msg(vport);
	}

	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10000));
}

/**
 * idpf_eth_adapter_alloc - Allocate ethernet adapter struct
 * @dev: Device struct
 * @num_max_vports: Number of vports
 */
static struct idpf_eth_adapter *idpf_eth_adapter_alloc(struct device *dev,
						       u16 num_max_vports)
{
	struct idpf_eth_adapter *adapter;

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return NULL;

	adapter->vports = kcalloc(num_max_vports, sizeof(*adapter->vports),
				  GFP_KERNEL);
	if (!adapter->vports) {
		kfree(adapter);
		return NULL;
	}

	adapter->netdevs = kcalloc(num_max_vports, sizeof(struct net_device *),
				   GFP_KERNEL);
	if (!adapter->netdevs)
		goto err_netdev_alloc;

	adapter->vport_config = kcalloc(num_max_vports,
					sizeof(*adapter->vport_config),
					GFP_KERNEL);
	if (!adapter->vport_config)
		goto err_vport_config_alloc;

	adapter->pre_init_wq = alloc_workqueue("%s-%s-prinit", 0, 0,
					       dev_driver_string(dev),
					       dev_name(dev));
	if (!adapter->pre_init_wq) {
		dev_err(dev, "Failed to allocate pre init workqueue\n");
		goto err_pre_init_wq_alloc;
	}

	adapter->post_init_wq = alloc_workqueue("%s-%s-pinit", 0, 0,
						dev_driver_string(dev),
						dev_name(dev));
	if (!adapter->post_init_wq) {
		dev_err(dev, "Failed to allocate post init workqueue\n");
				kfree(adapter);
		goto err_post_init_wq_alloc;
	}

	adapter->stats_wq = alloc_workqueue("%s-%s-stats", 0, 0,
					    dev_driver_string(dev),
					    dev_name(dev));
	if (!adapter->stats_wq) {
		dev_err(dev, "Failed to allocate workqueue\n");
		destroy_workqueue(adapter->post_init_wq);
		goto err_post_init_wq_alloc;
	}

	INIT_DELAYED_WORK(&adapter->pre_init_task,
			  idpf_eth_device_pre_init_task);
	INIT_DELAYED_WORK(&adapter->post_init_task,
			  idpf_eth_device_post_init_task);
	INIT_DELAYED_WORK(&adapter->stats_task, idpf_eth_statistics_task);
	mutex_init(&adapter->vport_ctrl_lock);

	return adapter;

err_post_init_wq_alloc:
	destroy_workqueue(adapter->pre_init_wq);
err_pre_init_wq_alloc:
	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
err_vport_config_alloc:
	kfree(adapter->netdevs);
	adapter->netdevs = NULL;
err_netdev_alloc:
	kfree(adapter->vports);
	adapter->vports = NULL;
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
	u16 num_default_vports;
	u16 index;

	num_default_vports = adapter->dev_info->default_vports;
	for (index = 0; index < num_default_vports; index++) {
		if (!(adapter->vports && adapter->vports[index]) ||
		    !(adapter->netdevs && adapter->netdevs[index]))
			continue;

		vport_config = adapter->vport_config[index];
		if (adapter->netdevs[index] &&
		    !test_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags)) {
			register_netdev(adapter->netdevs[index]);
			set_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags);
		}
	}

	/* Mark the ethernet driver initialize completion */
	set_bit(IDPF_ETH_INIT_COMPLETE, adapter->flags);

	/* Start the statistics task now */
	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10));
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

	/* Ready to finish the post init now */
	idpf_eth_device_post_init(adapter);
}

/**
 * idpf_vport_params_buf_rel - Release memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will release memory to hold the vport parameters received on MailBox
 */
static void idpf_vport_params_buf_rel(struct idpf_eth_adapter *adapter)
{
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
}

/**
 * idpf_vport_params_buf_alloc - Allocate memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will alloc memory to hold the vport parameters received on MailBox
 */
static int idpf_vport_params_buf_alloc(struct idpf_eth_adapter *adapter)
{
	u16 num_max_vports;

	num_max_vports = adapter->dev_info->default_vports;
	adapter->vport_params_reqd =
		kcalloc(num_max_vports,
			sizeof(*adapter->vport_params_reqd),
			GFP_KERNEL);
	if (!adapter->vport_params_reqd)
		return -ENOMEM;

	adapter->vport_params_recvd =
		kcalloc(num_max_vports,
			sizeof(*adapter->vport_params_recvd),
			GFP_KERNEL);
	if (!adapter->vport_params_recvd)
		goto err_mem;

	adapter->vport_ids = kcalloc(num_max_vports, sizeof(u32), GFP_KERNEL);
	if (!adapter->vport_ids)
		goto err_mem;

	return 0;

err_mem:
	idpf_vport_params_buf_rel(adapter);

	return -ENOMEM;
}

/**
 * idpf_eth_device_pre_init - Ethernet device pre initialization
 * @adapter: Ethernet private data structure
 */
static void idpf_eth_device_pre_init(struct idpf_eth_adapter *adapter)
{
	struct idpf_vport_config *vport_config;
	struct idpf_netdev_priv *np;
	struct idpf_max_q *max_q;
	struct idpf_vport *vport;
	u16 num_default_vports;
	struct device *dev;
	bool default_vport;
	int index, err;

	num_default_vports = adapter->dev_info->default_vports;
	if (adapter->dev_info->vport_type == IDPF_DEFAULT_VPORT)
		default_vport = true;
	else
		default_vport = false;

	max_q = &adapter->dev_info->caps.q_info[adapter->next_vport];
	err = idpf_send_create_vport_msg(adapter, max_q);
	if (err)
		goto unwind_vports;

	dev = idpf_adapter_to_pdev_dev(adapter);
	vport = idpf_vport_alloc(adapter, max_q);
	if (!vport) {
		err = -EFAULT;
		dev_err(dev, "failed to allocate vport: %d\n",	err);
		goto unwind_vports;
	}

	index = vport->idx;
	vport_config = adapter->vport_config[index];

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

	np = netdev_priv(vport->netdev);
	np->state = __IDPF_VPORT_DOWN;
	if (test_and_clear_bit(IDPF_VPORT_UP_REQUESTED, vport_config->flags))
		idpf_vport_open(vport, true);

	/* Spawn and return 'idpf_eth_device_pre_init_task' work queue
	 * until all the default vports are created
	 */
	if (adapter->num_alloc_vports < num_default_vports) {
		queue_delayed_work(adapter->pre_init_wq,
				   &adapter->pre_init_task,
				   msecs_to_jiffies(5));
		return;
	}

	/* Scheduling work for device's post-initialization */
	queue_delayed_work(adapter->post_init_wq, &adapter->post_init_task,
			   msecs_to_jiffies(5));

	return;

handle_err:
	idpf_decfg_netdev(vport);
cfg_netdev_err:
	idpf_vport_rel(vport);
	adapter->vports[index] = NULL;
unwind_vports:
	if (default_vport) {
		for (index = 0; index < num_default_vports; index++) {
			if (adapter->vports[index])
				idpf_vport_dealloc(adapter->vports[index], false);
		}
	}
}

/**
 * idpf_eth_device_pre_init_task - Ethernet pre initialization task
 * @work: work_struct handle to ethernet adapter data
 */
static void idpf_eth_device_pre_init_task(struct work_struct *work)
{
	struct idpf_eth_adapter *adapter;

	adapter = container_of(work, struct idpf_eth_adapter,
			       pre_init_task.work);

	/* Ready to finish the post init now */
	idpf_eth_device_pre_init(adapter);
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
	u16 num_max_vports;
	int err;

	eth_dev = container_of(adev, struct idpf_eth_idc_auxiliary_dev, adev);
	dev = &adev->dev;
	num_max_vports = eth_dev->eth_info.default_vports;
	adapter = eth_dev->eth_info.eth_context;
	if (!adapter) {
		adapter = idpf_eth_adapter_alloc(dev, num_max_vports);
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

	err = idpf_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(dev, "Failed to alloc vport params buffer: %d\n", err);
		goto err_buff_alloc;
	}

	/* Device's pre-initialization */
	idpf_eth_device_pre_init(adapter);

	return 0;

err_buff_alloc:
	adapter->vports = NULL;
	return err;
}

/**
 * idpf_eth_remove - removes ethernet device
 * @adev: Structure related to ethernet device information
 */
static void idpf_eth_remove(struct auxiliary_device *adev)
{
	struct idpf_eth_idc_auxiliary_dev *dev_info =
		container_of(adev, struct idpf_eth_idc_auxiliary_dev, adev);
	struct idpf_eth_adapter *adapter;
	struct net_device *netdev;
	u16 default_vports;
	u16 idx;

	adapter = dev_info->eth_info.eth_context;
	if (!adapter)
		return;

	default_vports = adapter->dev_info->default_vports;
	for (idx = 0; idx < default_vports; idx++) {
		if (adapter->netdevs) {
			netdev = adapter->netdevs[idx];
			if (netdev) {
				if (netdev->reg_state != NETREG_UNINITIALIZED)
					unregister_netdev(netdev);
				free_netdev(netdev);
				adapter->netdevs[idx] = NULL;
			}
		}
		if (adapter->vport_config) {
			kfree(adapter->vport_config[idx]);
			adapter->vport_config[idx] = NULL;
		}
	}

	idpf_vport_params_buf_rel(adapter);
	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
	kfree(adapter->netdevs);
	adapter->netdevs = NULL;
	kfree(adapter->vports);
	adapter->vports = NULL;

	destroy_workqueue(adapter->pre_init_wq);
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
		idpf_netdev_stop_all(adapter);
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
	unsigned int i;

	if (!adapter->vports)
		return;
	
	/* Acquire lock */
	mutex_lock(&adapter->vport_ctrl_lock);
	cancel_delayed_work_sync(&adapter->stats_task);
	/* Release lock before making system call */
	mutex_unlock(&adapter->vport_ctrl_lock);

	idpf_netdev_stop_all(adapter);

	/* Re-acquire lock */
	mutex_lock(&adapter->vport_ctrl_lock);

	for (i = 0; i < adapter->dev_info->default_vports; i++) {
		if (adapter->vports[i])
			idpf_vport_dealloc(adapter->vports[i], true);
	}

	/* Wait until the pre_init_task is done else this thread might release
	 * the resources first and the other thread might end up in a bad state
	 */
	cancel_delayed_work_sync(&adapter->pre_init_task);
	idpf_vport_params_buf_rel(adapter);

	/* Release lock */
	mutex_unlock(&adapter->vport_ctrl_lock);
}

