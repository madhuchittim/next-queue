// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"
#include "idpf_devids.h"

#define DRV_SUMMARY	"Intel(R) Infrastructure Data Path Function Linux Driver"

MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_IMPORT_NS(LIBETH);
MODULE_LICENSE("GPL");

/**
 * idpf_alloc_adapter - Allocate devlink and return adapter structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
static struct idpf_adapter *idpf_alloc_adapter(struct device *dev)
{
	static struct devlink_ops idpf_devlink_ops = {};
	struct devlink *devlink;

	devlink = devlink_alloc(&idpf_devlink_ops,
				sizeof(struct idpf_adapter), dev);
	if (!devlink)
		return NULL;

	return devlink_priv(devlink);
}

/**
 * idpf_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void idpf_remove(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	set_bit(IDPF_REMOVE_IN_PROG, idpf_adapter_flags(adapter));

	/* Wait until vc_event_task is done to consider if any hard reset is
	 * in progress else we may go ahead and release the resources but the
	 * thread doing the hard reset might continue the init path and
	 * end up in bad state.
	 */
	cancel_delayed_work_sync(&adapter->vc_event_task);
	if (adapter->num_vfs)
		idpf_sriov_configure(pdev, 0);

	if (test_bit(IDPF_VC_CORE_INIT, idpf_adapter_flags(adapter)) &&
	    !test_bit(IDPF_VC_XN_DOWN, idpf_adapter_flags(adapter))) {
		idpf_vc_xn_shutdown(adapter->vcxn_mngr);
		set_bit(IDPF_VC_XN_DOWN, idpf_adapter_flags(adapter));
	}

	idpf_eth_idc_device_deinit(adapter);
	idpf_vc_core_deinit(adapter);

	/* Be a good citizen and leave the device clean on exit */
	adapter->dev_ops.reg_ops.trigger_reset(adapter, IDPF_HR_FUNC_RESET);
	idpf_deinit_dflt_mbx(adapter);

	destroy_workqueue(adapter->serv_wq);
	destroy_workqueue(adapter->mbx_wq);
	destroy_workqueue(adapter->vc_event_wq);
	destroy_workqueue(adapter->idc_eth_init_wq);

	kfree(adapter->vcxn_mngr);
	adapter->vcxn_mngr = NULL;

	mutex_destroy(&adapter->reset_lock);
	mutex_destroy(&adapter->vector_lock);
	mutex_destroy(&adapter->queue_lock);
	mutex_destroy(&adapter->vc_buf_lock);

	idpf_eth_idc_deinit_shared(&adapter->eth_shared);
	pci_set_drvdata(pdev, NULL);

	devl_unregister(priv_to_devlink(adapter));
	devlink_free(priv_to_devlink(adapter));
}

/**
 * idpf_shutdown - PCI callback for shutting down device
 * @pdev: PCI device information struct
 */
static void idpf_shutdown(struct pci_dev *pdev)
{
	idpf_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

/**
 * idpf_cfg_hw - Initialize HW struct
 * @adapter: adapter to setup hw struct for
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_cfg_hw(struct idpf_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct idpf_hw *hw = &adapter->hw;

	hw->hw_addr = pcim_iomap_table(pdev)[0];
	if (!hw->hw_addr) {
		pci_err(pdev, "failed to allocate PCI iomap table\n");

		return -ENOMEM;
	}

	hw->back = adapter;

	return 0;
}

/**
 * idpf_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in idpf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct idpf_adapter *adapter;
	int err;

	adapter = idpf_alloc_adapter(dev);
	if (!adapter)
		return -ENOMEM;

	adapter->pdev = pdev;
	switch (ent->device) {
	case IDPF_DEV_ID_PF:
		idpf_dev_ops_init(adapter);
		break;
	case IDPF_DEV_ID_VF:
		idpf_vf_dev_ops_init(adapter);
		adapter->crc_enable = true;
		break;
	default:
		err = -ENODEV;
		dev_err(&pdev->dev, "Unexpected dev ID 0x%x in idpf probe\n",
			ent->device);
		goto err_free;
	}

	err = idpf_eth_idc_init_shared(&adapter->eth_shared);
	if (err)
		goto err_free;

	err = pcim_enable_device(pdev);
	if (err)
		goto err_free;

	err = pcim_iomap_regions(pdev, BIT(0), pci_name(pdev));
	if (err) {
		pci_err(pdev, "pcim_iomap_regions failed %pe\n", ERR_PTR(err));

		goto err_free;
	}

	/* set up for high or low dma */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		pci_err(pdev, "DMA configuration failed: %pe\n", ERR_PTR(err));

		goto err_free;
	}

	pci_set_master(pdev);
	pci_set_drvdata(pdev, adapter);

	devl_register(priv_to_devlink(adapter));

	adapter->serv_wq = alloc_workqueue("%s-%s-service", 0, 0,
					   dev_driver_string(dev),
					   dev_name(dev));
	if (!adapter->serv_wq) {
		dev_err(dev, "Failed to allocate service workqueue\n");
		err = -ENOMEM;
		goto err_serv_wq_alloc;
	}

	adapter->mbx_wq = alloc_workqueue("%s-%s-mbx", 0, 0,
					  dev_driver_string(dev),
					  dev_name(dev));
	if (!adapter->mbx_wq) {
		dev_err(dev, "Failed to allocate mailbox workqueue\n");
		err = -ENOMEM;
		goto err_mbx_wq_alloc;
	}

	adapter->vc_event_wq = alloc_workqueue("%s-%s-vc_event", 0, 0,
					       dev_driver_string(dev),
					       dev_name(dev));
	if (!adapter->vc_event_wq) {
		dev_err(dev, "Failed to allocate virtchnl event workqueue\n");
		err = -ENOMEM;
		goto err_vc_event_wq_alloc;
	}

	adapter->idc_eth_init_wq = alloc_workqueue("%s-%s-ethinit", 0, 0,
						   dev_driver_string(dev),
						   dev_name(dev));
	if (!adapter->idc_eth_init_wq) {
		dev_err(dev, "Failed to allocate Eth idc init workqueue\n");
		err = -ENOMEM;
		goto err_idc_eth_wq_alloc;
	}

	err = idpf_cfg_hw(adapter);
	if (err) {
		dev_err(dev, "Failed to configure HW structure for adapter: %d\n",
			err);
		goto err_cfg_hw;
	}

	mutex_init(&adapter->reset_lock);
	mutex_init(&adapter->vector_lock);
	mutex_init(&adapter->queue_lock);
	mutex_init(&adapter->vc_buf_lock);

	INIT_DELAYED_WORK(&adapter->serv_task, idpf_service_task);
	INIT_DELAYED_WORK(&adapter->mbx_task, idpf_mbx_task);
	INIT_DELAYED_WORK(&adapter->vc_event_task, idpf_vc_event_task);
	INIT_DELAYED_WORK(&adapter->idc_eth_init_task,
			  idpf_idc_eth_device_init_task);

	adapter->dev_ops.reg_ops.reset_reg_init(adapter);
	set_bit(IDPF_HR_DRV_LOAD, idpf_adapter_flags(adapter));
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));

	return 0;

err_cfg_hw:
	destroy_workqueue(adapter->idc_eth_init_wq);
err_idc_eth_wq_alloc:
	destroy_workqueue(adapter->vc_event_wq);
err_vc_event_wq_alloc:
	destroy_workqueue(adapter->mbx_wq);
err_mbx_wq_alloc:
	destroy_workqueue(adapter->serv_wq);
err_serv_wq_alloc:
err_free:
	idpf_eth_idc_deinit_shared(&adapter->eth_shared);
	kfree(adapter);
	return err;
}

/* idpf_pci_tbl - PCI Dev idpf ID Table
 */
static const struct pci_device_id idpf_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF)},
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_VF)},
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(pci, idpf_pci_tbl);

static struct pci_driver idpf_driver = {
	.name			= KBUILD_MODNAME,
	.id_table		= idpf_pci_tbl,
	.probe			= idpf_probe,
	.sriov_configure	= idpf_sriov_configure,
	.remove			= idpf_remove,
	.shutdown		= idpf_shutdown,
};

/**
 * idpf_driver_register - Device registration routine
 * @void: void
 *
 * Returns 0 on success, otherwise function returned on failure
 */
static int __init idpf_driver_register(void)
{
	int err;

	err = idpf_eth_idc_driver_register();
	if (err)
		return err;

	return  pci_register_driver(&idpf_driver);
}

/**
 * idpf_driver_unregister - Device unregister routine
 * @void: void
 *
 * Returns void
 */
static void __exit idpf_driver_unregister(void)
{
	idpf_eth_idc_driver_unregister();
	pci_unregister_driver(&idpf_driver);
}

module_init(idpf_driver_register);
module_exit(idpf_driver_unregister);
