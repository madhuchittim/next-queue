/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_NETDEV_H_
#define _IDPF_NETDEV_H_

/**
 * struct idpf_netdev_priv - Struct to store vport back pointer
 * @adapter: Adapter back pointer
 * @vport: Vport back pointer
 * @vport_id: Vport identifier
 * @vport_idx: Relative vport index
 * @state: See enum idpf_vport_state
 * @netstats: Packet and byte stats
 * @stats_lock: Lock to protect stats update
 */
struct idpf_netdev_priv {
	struct idpf_adapter *adapter;
	struct idpf_vport *vport;
	u32 vport_id;
	u16 vport_idx;
	enum idpf_vport_state state;
	struct rtnl_link_stats64 netstats;
	spinlock_t stats_lock;
};

/**
 * idpf_netdev_to_vport - get a vport handle from a netdev
 * @netdev: network interface device structure
 */
static inline struct idpf_vport *idpf_netdev_to_vport(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->vport;
}

/**
 * idpf_netdev_to_adapter - Get adapter handle from a netdev
 * @netdev: Network interface device structure
 */
static
inline struct idpf_adapter *idpf_netdev_to_adapter(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->adapter;
}

/**
 * idpf_vport_ctrl_lock - Acquire the vport control lock
 * @netdev: Network interface device structure
 *
 * This lock should be used by non-datapath code to protect against vport
 * destruction.
 */
static inline void idpf_vport_ctrl_lock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_lock(&np->adapter->vport_ctrl_lock);
}

/**
 * idpf_vport_ctrl_unlock - Release the vport control lock
 * @netdev: Network interface device structure
 */
static inline void idpf_vport_ctrl_unlock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_unlock(&np->adapter->vport_ctrl_lock);
}

int idpf_cfg_netdev(struct idpf_vport *vport);
void idpf_decfg_netdev(struct idpf_vport *vport);

#endif /* _IDPF_NETDEV_H_ */
