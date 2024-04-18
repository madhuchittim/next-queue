/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_ETH_H_
#define _IDPF_ETH_H_

#include <net/pkt_sched.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/sctp.h>
#include <linux/ethtool_netlink.h>
#include <net/gro.h>
#include <linux/dim.h>

#include "virtchnl2.h"
#include "idpf_controlq.h"
#include "idpf_eth_idc.h"
#include "idpf_lan_txrx.h"
#include "idpf_vport.h"

/* available message levels */
#define IDPF_AVAIL_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)
#define IDPF_TX_MIN_PKT_LEN		17

/**
 * enum idpf_eth_flags - Ethernet adapter flags.
 * @IDPF_ETH_RESET_IN_PROG: Indicates parent device's reset in progress
 * @IDPF_FLAGS_NBITS: Must be last
 */
enum idpf_eth_flags {
	IDPF_ETH_INIT_COMPLETE = 1,
	IDPF_ETH_RESET_IN_PROG,
	IDPF_ETH_REMOVE_IN_PROG,
	IDPF_ETH_FLAGS_NBITS,
};

/**
 * struct idpf_eth_adapter - ethernet device data struct generated on probe
 * @post_init_task: Ethernet probe's post init task
 * @post_init_wq: post init work queue
 * @flags: See enum idpf_eth_flags
 * @dev_info: Ethernet device information
 * @stats_task: Periodic statistics retrieval task
 * @stats_wq: Workqueue for statistics task
 * @vports: Array to store vports created by the driver
 * @netdevs: Associated Vport netdevs
 * @vport_params_reqd: Vport params requested
 * @vport_params_recvd: Vport params received
 * @vport_config: Vport config parameters
 * @vport_ctrl_lock: Lock to protect the vport control flow
 * @tx_timeout_count: Number of TX timeouts that have occurred
 * @req_tx_splitq: TX split or single queue model to request
 * @req_rx_splitq: RX split or single queue model to request
 * @vport_ids: Array of device given vport identifiers
 * @next_vport: Next free slot in pf->vport[] - 0-based!
 * @num_alloc_vports: Vport allocated count
 * @msg_enable: Debug message level enabled
 * @start_post_init: Starts probe post initialization 
 */
struct idpf_eth_adapter {
	struct delayed_work post_init_task;
	struct workqueue_struct *post_init_wq;
	DECLARE_BITMAP(flags, IDPF_ETH_FLAGS_NBITS);
	struct idpf_eth_idc_dev_info *dev_info;
	struct delayed_work stats_task;
	struct workqueue_struct *stats_wq;
	struct idpf_vport *vport;
	struct net_device *netdev;
	struct virtchnl2_create_vport *vport_params_reqd;
	struct virtchnl2_create_vport *vport_params_recvd;
	struct idpf_vport_config *vport_config;
	struct mutex vport_ctrl_lock;
	u32 tx_timeout_count;
	bool req_tx_splitq;
	bool req_rx_splitq;
	u32 *vport_ids;
	u16 next_vport;
	u16 num_alloc_vports;
	u32 msg_enable;
	bool start_post_init;
};

#define idpf_eth_adapter_shared(eth_adapter) \
	((eth_adapter)->dev_info->eth_shared)
#define idpf_eth_idc(eth_adapter) \
	((idpf_eth_adapter_shared(eth_adapter))->eth_idc_ops)
#define idpf_eth_caps(adapter) \
	(&((adapter)->dev_info->caps))
#define idpf_user_config(adapter) \
	(&(((adapter)->vport_config)->user_config))

/**
 * idpf_adapter_to_pdev_dev - Get device structure
 * @adapter: private data struct
 * 
 * Returns dev struct.
 */
static inline
struct device *idpf_adapter_to_pdev_dev(struct idpf_eth_adapter *adapter)
{
	struct idpf_eth_idc_dev_info *eth_dev_info = adapter->dev_info;
	struct idpf_eth_idc_auxiliary_dev *adev;

	adev = container_of(eth_dev_info,
			    struct idpf_eth_idc_auxiliary_dev,
			    eth_info);

	return adev->adev.dev.parent;
}

/**
 * idpf_eth_get_max_tx_bufs - Get max scatter-gather buffers
 * supported by the device
 * @adapter: private data struct
 */
static
inline unsigned int idpf_eth_get_max_tx_bufs(struct idpf_eth_adapter *adapter)
{
	return adapter->dev_info->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_eth_get_min_tx_pkt_len - Get min packet length supported by the device
 * @adapter: private data struct
 */
static inline u8 idpf_eth_get_min_tx_pkt_len(struct idpf_eth_adapter *adapter)
{
	u8 pkt_len = adapter->dev_info->caps.min_sso_packet_len;

	return pkt_len ? pkt_len : IDPF_TX_MIN_PKT_LEN;
}

/**
 * idpf_eth_get_max_tx_hdr_size -- get the size of tx header
 * @adapter: Ethernet driver specific private structure
 */
static inline u16 idpf_eth_get_max_tx_hdr_size(struct idpf_eth_adapter *adapter)
{
	return le16_to_cpu(adapter->dev_info->caps.max_tx_hdr_size);
}

/**
 * idpf_eth_get_reg_addr - reg operations
 * @eth_shared: Ethernet shared information
 * @reg_offset: Register offset
 */
static inline
void __iomem *idpf_eth_get_reg_addr(struct idpf_eth_shared *eth_shared,
				    resource_size_t reg_offset)
{
	return (void __iomem *)(eth_shared->hw_addr + reg_offset);
}

void idpf_eth_device_deinit(struct idpf_eth_adapter *adapter);
void idpf_eth_statistics_task(struct work_struct *work);
struct idpf_eth_idc_auxiliary_driver *idpf_eth_get_driver(void);

#endif /* !_IDPF_ETH_H_ */
