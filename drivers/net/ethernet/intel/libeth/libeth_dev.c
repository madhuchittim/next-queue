// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/libeth_dev.h>

/**
 * libeth_init_virtchnl_param - initialize the virtchnl param structure
 * @msg_param: pointer to virtchnl msg param
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @msg: pointer to virtchnl msg
 */
static void 
libeth_init_virtchnl_param(struct libeth_virtchnl_msg_param *msg_param,
			   struct libeth_hw *hw,
			   struct libeth_ctlq_info *ctlq_info,
			   struct libeth_ctlq_xn_manager *xnm,
			   struct libeth_virtchnl_msg *msg)
{
	msg_param->hw = hw;
	msg_param->msg = msg;
	msg_param->xnm = xnm;
	msg_param->ctlq_info = ctlq_info;
}

/**
 * libeth_create_vport - create vport
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @cv: pointer to create vport info buffer
 * @vport: pointer to vport
 */
int libeth_create_vport(struct libeth_hw *hw,
			struct libeth_ctlq_info *ctlq_info,
			struct libeth_ctlq_xn_manager *xnm,
			struct virtchnl2_create_vport *cv,
			struct libeth_vport **vport)
{
	struct libeth_virtchnl_msg_param msg_param = { 0 };
	struct libeth_virtchnl_msg msg = { 0 };
	int i, err;

	*vport = kzalloc(sizeof(**vport), GFP_KERNEL);
	if (!*vport)
		return -ENOMEM;

	msg.hw_opcode = libeth_mbq_opc_send_msg_to_cp;
	msg.virtchnl_opcode = VIRTCHNL2_OP_CREATE_VPORT;
	msg.send_buf.iov_base = cv;
	msg.send_buf.iov_len = sizeof(*cv);
	msg.recv_buf.iov_base = cv;
	msg.recv_buf.iov_len = sizeof(*cv);
	libeth_init_virtchnl_param(&msg_param, hw, ctlq_info, xnm, &msg);

	err = libeth_send_virtchnl_msg(&msg_param);
	if (err)
		goto error_exit;
	(*vport)->vport_type = le16_to_cpu(cv->vport_type);
	(*vport)->vport_id = le32_to_cpu(cv->vport_id);
	(*vport)->max_mtu = le16_to_cpu(cv->max_mtu);
	for (i=0; i < ETH_ALEN; i++)
		(*vport)->default_mac_addr[i] = cv->default_mac_addr[i];

	return 0;

error_exit:
	kfree(*vport);
	*vport = NULL;

	return err;
}
EXPORT_SYMBOL(libeth_create_vport);

/**
 * libeth_remove_vport - remove vport
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @vport: pointer to vport info
 */
int libeth_remove_vport(struct libeth_hw *hw,
			struct libeth_ctlq_info *ctlq_info,
			struct libeth_ctlq_xn_manager *xnm,
			struct libeth_vport **vport)
{
	struct libeth_virtchnl_msg_param msg_param = { 0 };
	struct virtchnl2_create_vport vport_info = { 0 };
	struct libeth_virtchnl_msg msg = { 0 };
	int err;

	vport_info.vport_id = (*vport)->vport_id;
	msg.hw_opcode = libeth_mbq_opc_send_msg_to_cp;
	msg.virtchnl_opcode = VIRTCHNL2_OP_DESTROY_VPORT;
	msg.send_buf.iov_base = &vport_info;
	msg.send_buf.iov_len = sizeof(vport_info);
	libeth_init_virtchnl_param(&msg_param, hw, ctlq_info, xnm, &msg);

	err = libeth_send_virtchnl_msg(&msg_param);
	if (!err) {
		kfree(*vport);
		*vport = NULL;
	}

	return err;
}
EXPORT_SYMBOL(libeth_remove_vport);

/**
 * libeth_get_caps - Get device capability
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @caps: pointer to virtchnl capability msg resp buffer
 */
int libeth_get_caps(struct libeth_hw *hw,
		    struct libeth_ctlq_info *ctlq_info,
		    struct libeth_ctlq_xn_manager *xnm,
		    struct virtchnl2_get_capabilities *caps)
{
	struct libeth_virtchnl_msg_param msg_param = { 0 };
	struct libeth_virtchnl_msg msg = { 0 };

	msg.hw_opcode = libeth_mbq_opc_send_msg_to_cp;
	msg.virtchnl_opcode = VIRTCHNL2_OP_GET_CAPS;
	msg.recv_buf.iov_base = caps;
	msg.recv_buf.iov_len = sizeof(*caps);
	libeth_init_virtchnl_param(&msg_param, hw, ctlq_info, xnm, &msg);

	return libeth_send_virtchnl_msg(&msg_param);
}
EXPORT_SYMBOL(libeth_get_caps);

/**
 * libeth_get_version - Get version
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @version: pointer to virtchnl version msg req/resp buffer
 */
int libeth_get_version(struct libeth_hw *hw,
		       struct libeth_ctlq_info *ctlq_info,
		       struct libeth_ctlq_xn_manager *xnm,
		       struct virtchnl2_version_info *version)
{
	struct libeth_virtchnl_msg_param msg_param = { 0 };
	struct libeth_virtchnl_msg msg = { 0 };

	msg.hw_opcode = libeth_mbq_opc_send_msg_to_cp;
	msg.virtchnl_opcode = VIRTCHNL2_OP_VERSION;
	msg.send_buf.iov_base = version;
	msg.send_buf.iov_len = sizeof(*version);
	msg.recv_buf.iov_base = version;
	msg.recv_buf.iov_len = sizeof(*version);
	libeth_init_virtchnl_param(&msg_param, hw, ctlq_info, xnm, &msg);

	return libeth_send_virtchnl_msg(&msg_param);
}
EXPORT_SYMBOL(libeth_get_version);

/**
 * libeth_trigger_reset - Trigger reset
 * @hw: hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 */
void libeth_trigger_reset(struct libeth_hw *hw,
		       struct libeth_ctlq_info *ctlq_info,
		       struct libeth_ctlq_xn_manager *xnm)
{
	struct libeth_virtchnl_msg_param msg_param = { 0 };
	struct libeth_virtchnl_msg msg = { 0 };

	msg.hw_opcode = libeth_mbq_opc_send_msg_to_cp;
	msg.virtchnl_opcode = VIRTCHNL2_OP_RESET_VF;
	libeth_init_virtchnl_param(&msg_param, hw, ctlq_info, xnm, &msg);

	libeth_send_virtchnl_msg(&msg_param);
}
EXPORT_SYMBOL(libeth_trigger_reset);


/**
 * libeth_dev_state_init - State machine initialization
 * @hw: Hardware specific structure
 * @ctlq_info: pointer to the specific Control queue
 * @xnm: transaction manager
 * @version: pointer to virtchnl version msg req/resp buffer
 * @caps: pointer to virtchnl capability msg resp buffer
 * @state: Device state
  */
int libeth_dev_state_init(struct libeth_hw *hw,
			  struct libeth_ctlq_info *ctlq_info,
			  struct libeth_ctlq_xn_manager *xnm,
			  struct virtchnl2_version_info *version,
			  struct virtchnl2_get_capabilities *caps,
			  enum libeth_dev_state *state)
{
	int task_delay = 30;
	int err = 0;

	*state = __LIBETH_VER_CHECK;

	while (*state != __LIBETH_INIT_SW) {
		switch (*state) {
		case __LIBETH_VER_CHECK:
			err = libeth_get_version(hw, ctlq_info, xnm, version);
			switch (err) {
			case 0:
				/* success, move state machine forward */
				*state = __LIBETH_GET_CAPS;
				fallthrough;
			case -EAGAIN:
				goto restart;
			default:
				/* Something bad happened, try again but only a
				 * few times.
				 */
				goto init_failed;
			}
		case __LIBETH_GET_CAPS:
			err = libeth_get_caps(hw, ctlq_info, xnm, caps);
			if (err)
				goto init_failed;
			*state = __LIBETH_INIT_SW;
			break;
		default:
			err = -EINVAL;
			goto init_failed;
		}
		break;
restart:
		/* Give enough time before proceeding further with
		 * state machine
		 */
		msleep(task_delay);
	}
	return 0;

init_failed:
	*state = __LIBETH_VER_CHECK;

	return err;
}
EXPORT_SYMBOL(libeth_dev_state_init);

/**
 * libeth_find_ctlq - find the control q based on type
 * @hw: Hardware specific structure
 * @type: TX or RX queue type
 * @id: queue identifier
 */
struct libeth_ctlq_info *
libeth_find_ctlq(struct libeth_hw *hw, enum virtchnl2_queue_type type, int id)
{
	struct libeth_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
	if (cq->q_id == id && cq->cq_type == type)
		return cq;

	return NULL;
}
EXPORT_SYMBOL(libeth_find_ctlq);

/**
 * libeth_ctlq_reg_init - Initialize the mailbox registers
 * @cq: control queue info
 * @ctlq_reg_tx: Transmit queue registers
 * @ctlq_reg_rx: Receive queue registers
 */
static void libeth_ctlq_reg_init(struct libeth_ctlq_create_info *cq,
				 struct libeth_ctlq_reg *ctlq_reg_tx,
				 struct libeth_ctlq_reg *ctlq_reg_rx)
{
	int i;

	for (i = 0; i < LIBETH_NUM_DFLT_MBX_Q; i++) {
		struct libeth_ctlq_create_info *ccq = cq + i;

		switch (ccq->type) {
		case VIRTCHNL2_QUEUE_TYPE_TX:
			/* set head and tail registers in our local struct */
			ccq->reg.head = ctlq_reg_tx->head;
			ccq->reg.tail = ctlq_reg_tx->tail;
			ccq->reg.len = ctlq_reg_tx->len;
			ccq->reg.bah = ctlq_reg_tx->bah;
			ccq->reg.bal = ctlq_reg_tx->bal;
			ccq->reg.len_mask = ctlq_reg_tx->len_mask;
			ccq->reg.len_ena_mask = ctlq_reg_tx->len_ena_mask;
			ccq->reg.head_mask = ctlq_reg_tx->head_mask;
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX:
			/* set head and tail registers in our local struct */
			ccq->reg.head = ctlq_reg_rx->head;
			ccq->reg.tail = ctlq_reg_rx->tail;
			ccq->reg.len = ctlq_reg_rx->len;
			ccq->reg.bah = ctlq_reg_rx->bah;
			ccq->reg.bal = ctlq_reg_rx->bal;
			ccq->reg.len_mask = ctlq_reg_rx->len_mask;
			ccq->reg.len_ena_mask = ctlq_reg_rx->len_ena_mask;
			ccq->reg.head_mask = ctlq_reg_rx->head_mask;
			break;
		default:
			break;
		}
	}
}

/**
 * libeth_init_dflt_mbx - Initialize default mailbox
 * @hw: Hardware specific structure
 * @xnm: Transaction manager
 * @ctlq_reg_tx: mailbox tx registers
 * @ctlq_reg_rx: mailbox rx registers
 */
int libeth_init_dflt_mbx(struct libeth_hw *hw, 
			 struct libeth_ctlq_xn_manager **xnm,
			 struct libeth_ctlq_reg *ctlq_reg_tx,
			 struct libeth_ctlq_reg *ctlq_reg_rx)
{
	struct libeth_ctlq_create_info ctlq_info[] = {
		{
			.type = VIRTCHNL2_QUEUE_TYPE_TX,
			.id = LIBETH_DFLT_MBX_ID,
			.len = LIBETH_DFLT_MBX_Q_LEN,
			.buf_size = LIBETH_CTLQ_MAX_BUF_LEN
		},
		{
			.type = VIRTCHNL2_QUEUE_TYPE_RX,
			.id = LIBETH_DFLT_MBX_ID,
			.len = LIBETH_DFLT_MBX_Q_LEN,
			.buf_size = LIBETH_CTLQ_MAX_BUF_LEN
		}
	};
	struct libeth_ctlq_xn_init_params params = { };
	int err;

	/* Do error checking */
	if (!hw || !xnm)
		return -EINVAL;

	libeth_ctlq_reg_init(ctlq_info, ctlq_reg_tx, ctlq_reg_rx);

	/* Initialize mailbox and Transaction(XN) */
	params.num_qs = LIBETH_NUM_DFLT_MBX_Q;
	params.cctlq_info = ctlq_info;
	params.hw = hw;
	err = libeth_ctlq_xn_init(&params);
	if (err)
		return err;
	*xnm = params.xnm;

	return 0;
}
EXPORT_SYMBOL(libeth_init_dflt_mbx);

/**
 * libeth_deinit_dflt_mbx - Deinitialize default mailbox
 * @hw: Hardware specific structure
 * @xnm: Transaction manager
 */
int libeth_deinit_dflt_mbx(struct libeth_hw *hw,
			   struct libeth_ctlq_xn_manager *xnm)
{
	struct libeth_ctlq_xn_init_params params = { };

	if (!xnm)
		return -EINVAL;

	params.hw = hw;
	params.xnm = xnm;
	libeth_ctlq_xn_deinit(&params);

	return 0;
}
EXPORT_SYMBOL(libeth_deinit_dflt_mbx);

/**
 * libeth_is_reset_detected - Check if reset is detected
 * @hw: Hardware specific structure
 * @ctlq_info: control queue to check the queue len
 */
bool libeth_is_reset_detected(struct libeth_hw *hw,
			      struct libeth_ctlq_info *ctlq_info)
{
	volatile void __iomem *addr;
	u32 offset, mask;

	if (!ctlq_info)
		return true;

	offset = ctlq_info->reg.len; /* length offset */
	mask = ctlq_info->reg.len_mask;
	addr = libeth_get_mmio_addr(hw, offset);
	if (!addr)
		return true;
	return !((readl(addr) & mask));
}
EXPORT_SYMBOL(libeth_is_reset_detected);

/**
 * libeth_check_reset_complete - Check if reset is complete
 * @hw: Hardware specific structure
 * @reset_reg: reset register information
 */
int libeth_check_reset_complete(struct libeth_hw *hw,
				struct libeth_reset_reg *reset_reg)
{
	int i;

	for (i = 0; i < 2000; i++) {
		u32 reg_val = readl(reset_reg->rstat);

		/* 0xFFFFFFFF might be read if other side hasn't cleared the
		 * register for us yet and 0xFFFFFFFF is not a valid value for
		 * the register, so treat that as invalid.
		 */
		if (reg_val != 0xFFFFFFFF && (reg_val & reset_reg->rstat_m))
			return 0;

		usleep_range(5000, 10000);
	}

	return -EBUSY;
}
EXPORT_SYMBOL(libeth_check_reset_complete);

/**
 * libeth_pf_trigger_reset - Trigger reset
 * @hw: Hardware specific structure
 * @reset_reg: reset registers information
 */
void libeth_pf_trigger_reset(struct libeth_hw *hw,
			     struct libeth_reset_reg *reset_reg)
{
	u32 reset_data;

	reset_data = readl(reset_reg->rtrigger);
	writel(reset_data | reset_reg->rtrigger_m, reset_reg->rtrigger);
}
EXPORT_SYMBOL(libeth_pf_trigger_reset);

/**
 * libeth_setup_device - Initialize device specific resources
 * @pdev: pci device
 */
int libeth_setup_device(struct pci_dev *pdev)
{
	int err;

	err = pcim_enable_device(pdev);
	if (err) {
		pci_err(pdev, "pcim_enable_device failed %pe\n", ERR_PTR(err));
		return err;
	}

	err = pci_request_mem_regions(pdev, pci_name(pdev));
	if (err) {
		pci_err(pdev, "pci request mem regions failed %pe\n",
			ERR_PTR(err));
		return err;
	}

	/* set up for high or low dma */
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		pci_err(pdev, "DMA configuration failed: %pe\n", ERR_PTR(err));
		return err;
	}
	pci_set_master(pdev);

	return 0;
}
EXPORT_SYMBOL(libeth_setup_device);

/**
 * libeth_cfg_netdev - Allocate and initialize the net device
 * @vport: pointer to vport info
 * @dev_ops: pointer to device specific ops table
 * @ethtool_ops: pointer to ethtool ops table
 * @private_data_size: private data structure size
 */
int libeth_cfg_netdev(struct libeth_vport *vport,
		      struct net_device_ops *dev_ops,
		      struct ethtool_ops *ethtool_ops, int private_data_size)
{
	netdev_features_t dflt_features;
	netdev_features_t offloads;
	struct net_device *netdev;

	/* netdev registration */
	if (vport->netdev) {
		register_netdev(vport->netdev);
		return 0;
	}

	dflt_features = vport->dflt_features;
	offloads = vport->offloads;
	netdev = alloc_etherdev_mqs(private_data_size, vport->max_txq,
				    vport->max_rxq);
	if (!netdev)
		return -ENOMEM;

	netdev->netdev_ops = dev_ops;
	netdev->ethtool_ops = ethtool_ops;
	netdev->watchdog_timeo = 5 * HZ;
	netdev->mtu = min_t(unsigned int, netdev->mtu, vport->max_mtu);
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = vport->max_mtu;
	netdev->features |= dflt_features;
	netdev->hw_features |= (dflt_features | offloads);
	netdev->hw_enc_features |= (dflt_features | offloads);
	//netdev->dev_port = idx; base driver needs to set a unique value
	//netdev->gso_partial_features = 0; base driver needs to set this value
	eth_hw_addr_set(netdev, vport->default_mac_addr);
	ether_addr_copy(netdev->perm_addr, vport->default_mac_addr);
	
	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	vport->netdev = netdev;

	return 0;
}
EXPORT_SYMBOL(libeth_cfg_netdev);

/**
 * libeth_decfg_netdev - Unregister the netdev
 * @vport: vport for which netdev to be unregistered
 */
void libeth_decfg_netdev(struct libeth_vport *vport)
{
	unregister_netdev(vport->netdev);
	free_netdev(vport->netdev);
	vport->netdev = NULL;
}
EXPORT_SYMBOL(libeth_decfg_netdev);

