
/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_ETH_H_
#define _IDPF_ETH_H_

#include "idpf.h"

/**
 * struct idpf_mac_filter
 * @list: list member field
 * @macaddr: MAC address
 * @remove: filter should be removed (virtchnl)
 * @add: filter should be added (virtchnl)
 */
struct idpf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	bool remove;
	bool add;
};
/**
 * enum idpf_eth_flags - Ethernet adapter flags.
 * @IDPF_ETH_RESET_IN_PROG: Indicates parent device's reset in progress
 * @IDPF_FLAGS_NBITS: Must be last
 */
enum idpf_eth_flags {
	IDPF_ETH_RESET_IN_PROG,
	IDPF_ETH_REMOVE_IN_PROG,
	IDPF_ETH_FLAGS_NBITS,
};

/**
 * struct idpf_eth_adapter - ethernet device data struct
 * @wq: work queue
 * @flags: See enum idpf_eth_flags
 * @dev_info: Ethernet device information
 * @stats_task: Periodic statistics retrieval task
 * @stats_wq: Workqueue for statistics task
 * @vports: Array to store vports created by the driver
 * @netdev: Associated netdev
 * @vport_params_reqd: Vport params requested
 * @vport_params_recvd: Vport params received
 * @vport_config: Vport config parameters
 * @ctrl_lock: Lock to protect the adapter info
 * @tx_timeout_count: Number of TX timeouts that have occurred
 * @req_tx_splitq: TX split or single queue model to request
 * @req_rx_splitq: RX split or single queue model to request
 * @msg_enable: Debug message level enabled
 */
struct idpf_eth_adapter {
	struct idpf_vport *vport;
	struct net_device *netdev;
	struct idpf_vport_config vport_config;
	struct idpf_aux_dev_info *dev_info;
	DECLARE_BITMAP(flags, IDPF_ETH_FLAGS_NBITS);
	struct virtchnl2_create_vport *vport_params_reqd;
	struct virtchnl2_create_vport *vport_params_recvd;

	struct workqueue_struct *wq;
	struct delayed_work stats_task;

	struct mutex ctrl_lock;
	u32 tx_timeout_count;
	bool req_tx_splitq;
	bool req_rx_splitq;
	u32 msg_enable;
};

/**
 * struct idpf_netdev_priv - Struct to store vport back pointer
 * @adapter: Adapter back pointer
 * @vport: Vport back pointer
 * @vport_id: Vport identifier
 * @link_speed_mbps: Link speed in mbps
 * @state: See enum idpf_vport_state
 * @netstats: Packet and byte stats
 * @stats_lock: Lock to protect stats update
 */
struct idpf_netdev_priv {
	struct idpf_eth_adapter *adapter;
	struct idpf_vport *vport;
	u32 vport_id;
	u32 link_speed_mbps;
	enum idpf_vport_state state;
	struct rtnl_link_stats64 netstats;
	spinlock_t stats_lock;
};

/**
 * idpf_eth_is_reset_in_prog - check if reset is in progress
 * @adapter: driver specific private structure
 *
 * Returns true if hard reset is in progress, false otherwise
 */
static inline bool idpf_eth_is_reset_in_prog(struct idpf_eth_adapter *adapter)
{
	return (test_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags) ||
		test_bit(IDPF_ETH_REMOVE_IN_PROG, adapter->flags));
}

/**
 * idpf_netdev_to_vport - get a vport handle from a netdev
 * @netdev: network interface device structure
 */
static inline
struct idpf_vport *idpf_netdev_to_vport(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->vport;
}

/**
 * idpf_netdev_to_adapter - Get adapter handle from a netdev
 * @netdev: Network interface device structure
 */
static inline
struct idpf_eth_adapter *idpf_netdev_to_adapter(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->adapter;
}

/**
 * idpf_eth_to_aux - Get auxiliary device from Ethernet adapter
 * @adapter: Ethernet adapter device structure
 */
static inline
struct idpf_auxiliary_device *idpf_eth_to_aux(struct idpf_eth_adapter *adapter)
{
	struct idpf_auxiliary_device *aux_dev;

	aux_dev = container_of(adapter->dev_info, struct idpf_auxiliary_device,
			       aux_info);
	return aux_dev;
}

/**
 * idpf_eth_ctrl_lock - Acquire the adapter control lock
 * @netdev: Network interface device structure
 *
 */
static inline void idpf_eth_ctrl_lock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_lock(&np->adapter->ctrl_lock);
}

/**
 * idpf_eth_ctrl_unlock - Release the vport control lock
 * @netdev: Network interface device structure
 */
static inline void idpf_eth_ctrl_unlock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_unlock(&np->adapter->ctrl_lock);
}

/**
 * idpf_is_feature_ena - Determine if a particular feature is enabled
 * @vport: Vport to check
 * @feature: Netdev flag to check
 *
 * Returns true or false if a particular feature is enabled.
 */
static inline bool idpf_is_feature_ena(const struct idpf_vport *vport,
				       netdev_features_t feature)
{
	return vport->netdev->features & feature;
}

/**
 * idpf_get_max_tx_bufs - Get max scatter-gather buffers supported by the device
 * @adapter: private data struct
 */
static inline unsigned int idpf_get_max_tx_bufs(struct idpf_eth_adapter *adapter)
{
	return adapter->dev_info->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_get_min_tx_pkt_len - Get min packet length supported by the device
 * @adapter: private data struct
 */
static inline u8 idpf_get_min_tx_pkt_len(struct idpf_eth_adapter *adapter)
{
	u8 pkt_len = adapter->dev_info->caps.min_sso_packet_len;

	return pkt_len ? pkt_len : IDPF_TX_MIN_PKT_LEN;
}

/**
 * idpf_get_max_tx_hdr_size -- get the size of tx header
 * @adapter: private data struct
 */
static inline u16 idpf_get_max_tx_hdr_size(struct idpf_eth_adapter *adapter)
{
	return le16_to_cpu(adapter->dev_info->caps.max_tx_hdr_size);
}

void idpf_set_ethtool_ops(struct net_device *netdev);
struct idpf_auxiliary_driver* idpf_eth_get_driver(void);

#endif /* _IDPF_ETH_H_ */

