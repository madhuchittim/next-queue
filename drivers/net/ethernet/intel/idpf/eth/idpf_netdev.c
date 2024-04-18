// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf_eth.h"
#include "idpf_netdev.h"
#include "idpf_fltr.h"

static const struct net_device_ops idpf_netdev_ops_splitq;
static const struct net_device_ops idpf_netdev_ops_singleq;

/**
 * idpf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: TX queue
 */
void idpf_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct idpf_eth_adapter *adapter = idpf_netdev_to_adapter(netdev);
	struct idpf_eth_idc_event event;

	adapter->tx_timeout_count++;

	netdev_err(netdev, "Detected Tx timeout: Count %d, Queue %d\n",
		   adapter->tx_timeout_count, txqueue);
	event.event_code = IDPF_ETH_IDC_EVENT_REQ_HARD_RESET;
	idpf_eth_idc(adapter).event_send(adapter->dev_info, &event);
}

/**
 * idpf_netdev_stop - Stop traffic from getting queued up
 * @netdev: stack net device
 */
void idpf_netdev_stop(struct net_device *netdev)
{
	if (!netdev)
		return;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);
}

/**
 * idpf_cfg_netdev - Allocate, configure and register a netdev
 * @vport: main vport structure
 *
 * Returns 0 on success, negative value on failure.
 */
int idpf_cfg_netdev(struct idpf_vport *vport)
{
	struct idpf_eth_adapter *adapter = vport->adapter;
	struct idpf_eth_idc_auxiliary_dev_caps *caps;
	struct idpf_vport_config *vport_config;
	netdev_features_t dflt_features;
	netdev_features_t offloads = 0;
	struct idpf_netdev_priv *np;
	struct net_device *netdev;
	u16 idx = vport->idx;
	struct device *dev;
	int err;

	dev = idpf_adapter_to_pdev_dev(adapter);
	caps = idpf_eth_caps(adapter);
	vport_config = adapter->vport_config;

	/* It's possible we already have a netdev allocated and registered for
	 * this vport
	 */
	if (test_bit(IDPF_VPORT_REG_NETDEV, vport_config->flags)) {
		netdev = adapter->netdev;
		np = netdev_priv(netdev);
		np->vport = vport;
		np->vport_idx = vport->idx;
		np->vport_id = vport->vport_id;
		vport->netdev = netdev;
		return idpf_init_mac_addr(vport, netdev);
	}

	netdev = alloc_etherdev_mqs(sizeof(struct idpf_netdev_priv),
				    vport_config->max_q.max_txq,
				    vport_config->max_q.max_rxq);
	if (!netdev)
		return -ENOMEM;

	vport->netdev = netdev;
	np = netdev_priv(netdev);
	np->vport = vport;
	np->adapter = adapter;
	np->vport_idx = vport->idx;
	np->vport_id = vport->vport_id;

	spin_lock_init(&np->stats_lock);

	err = idpf_init_mac_addr(vport, netdev);
	if (err) {
		free_netdev(vport->netdev);
		vport->netdev = NULL;
		return err;
	}

	/* assign netdev_ops */
	if (idpf_is_queue_model_split(vport->txq_model))
		netdev->netdev_ops = &idpf_netdev_ops_splitq;
	else
		netdev->netdev_ops = &idpf_netdev_ops_singleq;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

	netdev->dev_port = idx;

	/* configure default MTU size */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = vport->max_mtu;

	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA;

	if (idpf_is_cap_ena_all(caps, IDPF_RSS_CAPS, IDPF_CAP_RSS))
		dflt_features |= NETIF_F_RXHASH;
	if (idpf_is_cap_ena_all(caps, IDPF_CSUM_CAPS,
				IDPF_CAP_RX_CSUM_L4V4))
		dflt_features |= NETIF_F_IP_CSUM;
	if (idpf_is_cap_ena_all(caps, IDPF_CSUM_CAPS,
				IDPF_CAP_RX_CSUM_L4V6))
		dflt_features |= NETIF_F_IPV6_CSUM;
	if (idpf_is_cap_ena(caps, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM))
		dflt_features |= NETIF_F_RXCSUM;
	if (idpf_is_cap_ena_all(caps, IDPF_CSUM_CAPS, IDPF_CAP_SCTP_CSUM))
		dflt_features |= NETIF_F_SCTP_CRC;

	if (idpf_is_cap_ena(caps, IDPF_SEG_CAPS,
			    VIRTCHNL2_CAP_SEG_IPV4_TCP))
		dflt_features |= NETIF_F_TSO;
	if (idpf_is_cap_ena(caps, IDPF_SEG_CAPS,
			    VIRTCHNL2_CAP_SEG_IPV6_TCP))
		dflt_features |= NETIF_F_TSO6;
	if (idpf_is_cap_ena_all(caps, IDPF_SEG_CAPS,
				VIRTCHNL2_CAP_SEG_IPV4_UDP |
				VIRTCHNL2_CAP_SEG_IPV6_UDP))
		dflt_features |= NETIF_F_GSO_UDP_L4;
	if (idpf_is_cap_ena_all(caps, IDPF_RSC_CAPS, IDPF_CAP_RSC))
		offloads |= NETIF_F_GRO_HW;
	/* advertise to stack only if offloads for encapsulated packets is
	 * supported
	 */
	if (idpf_is_cap_ena(caps, IDPF_SEG_CAPS,
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL)) {
		offloads |= NETIF_F_GSO_UDP_TUNNEL	|
			    NETIF_F_GSO_GRE		|
			    NETIF_F_GSO_GRE_CSUM	|
			    NETIF_F_GSO_PARTIAL		|
			    NETIF_F_GSO_UDP_TUNNEL_CSUM	|
			    NETIF_F_GSO_IPXIP4		|
			    NETIF_F_GSO_IPXIP6		|
			    0;

		if (!idpf_is_cap_ena_all(caps, IDPF_CSUM_CAPS,
					 IDPF_CAP_TUNNEL_TX_CSUM))
			netdev->gso_partial_features |=
				NETIF_F_GSO_UDP_TUNNEL_CSUM;

		netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
		offloads |= NETIF_F_TSO_MANGLEID;
	}
	if (idpf_is_cap_ena(caps, IDPF_OTHER_CAPS,
			    VIRTCHNL2_CAP_LOOPBACK))
		offloads |= NETIF_F_LOOPBACK;

	netdev->features |= dflt_features;
	netdev->hw_features |= dflt_features | offloads;
	netdev->hw_enc_features |= dflt_features | offloads;
	idpf_set_ethtool_ops(netdev);
	SET_NETDEV_DEV(netdev, dev);

	/* carrier off on init to avoid Tx hangs */
	netif_carrier_off(netdev);

	/* make sure transmit queues start off as stopped */
	netif_tx_stop_all_queues(netdev);

	/* The vport can be arbitrarily released so we need to also track
	 * netdevs in the adapter struct
	 */
	adapter->netdev = netdev;
	return 0;
}

/**
 * idpf_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state.  The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int idpf_stop(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport;

	idpf_vport_ctrl_lock(netdev);

	if (test_bit(IDPF_ETH_RESET_IN_PROG, np->adapter->flags)) {
		idpf_vport_ctrl_unlock(netdev);

		return -EBUSY; /* Temporarily busy indication */
	}

	vport = idpf_netdev_to_vport(netdev);

	idpf_vport_stop(vport);

	idpf_vport_ctrl_unlock(netdev);

	return 0;
}

/**
 * idpf_decfg_netdev - Unregister the netdev
 * @vport: vport for which netdev to be unregistered
 */
void idpf_decfg_netdev(struct idpf_vport *vport)
{
	struct idpf_eth_adapter *adapter = vport->adapter;

	/* Check first if netdev is registered earlier */
	if (test_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config->flags)) {
		unregister_netdev(vport->netdev);
		clear_bit(IDPF_VPORT_REG_NETDEV, adapter->vport_config->flags);
	}

	free_netdev(vport->netdev);
	vport->netdev = NULL;
	adapter->netdev = NULL;
}

/**
 * idpf_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static void idpf_get_stats64(struct net_device *netdev,
			     struct rtnl_link_stats64 *stats)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	spin_lock_bh(&np->stats_lock);
	*stats = np->netstats;
	spin_unlock_bh(&np->stats_lock);
}

/**
 * idpf_addr_sync - Callback for dev_(mc|uc)_sync to add address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this, we have to add the
 * filter and send the virtchnl message asynchronously without waiting for the
 * response from the other side. We won't know whether or not the operation
 * actually succeeded until we get the message back.  Returns 0 on success,
 * negative on failure.
 */
static int idpf_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return idpf_add_mac_filter(np->vport, np, addr, true);
}

/**
 * idpf_addr_unsync - Callback for dev_(mc|uc)_sync to remove address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this we have to delete the
 * filter and send the virtchnl message asynchronously without waiting for the
 * return from the other side.  We won't know whether or not the operation
 * actually succeeded until we get the message back. Returns 0 on success,
 * negative on failure.
 */
static int idpf_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	/* Under some circumstances, we might receive a request to delete
	 * our own device address from our uc list. Because we store the
	 * device address in the VSI's MAC filter list, we need to ignore
	 * such requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	idpf_del_mac_filter(np->vport, np, addr, true);

	return 0;
}

/**
 * idpf_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 *
 * Stack takes addr_list_lock spinlock before calling our .set_rx_mode.  We
 * cannot sleep in this context.
 */
static void idpf_set_rx_mode(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport_user_config_data *config_data;
	struct idpf_eth_idc_auxiliary_dev_caps *caps;
	struct idpf_eth_adapter *adapter;
	bool changed = false;
	struct device *dev;
	int err;

	adapter = np->adapter;
	dev = idpf_adapter_to_pdev_dev(adapter);
	caps = &adapter->dev_info->caps;

	if (idpf_is_cap_ena(caps, IDPF_OTHER_CAPS,
			    VIRTCHNL2_CAP_MACFILTER)) {
		__dev_uc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
		__dev_mc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
	}

	if (!idpf_is_cap_ena(caps, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_PROMISC))
		return;

	config_data = &adapter->vport_config->user_config;
	/* IFF_PROMISC enables both unicast and multicast promiscuous,
	 * while IFF_ALLMULTI only enables multicast such that:
	 *
	 * promisc  + allmulti		= unicast | multicast
	 * promisc  + !allmulti		= unicast | multicast
	 * !promisc + allmulti		= multicast
	 */
	if ((netdev->flags & IFF_PROMISC) &&
	    !test_and_set_bit(__IDPF_PROMISC_UC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Entering promiscuous mode\n");
		if (!test_and_set_bit(__IDPF_PROMISC_MC, config_data->user_flags))
			dev_info(dev, "Entering multicast promiscuous mode\n");
	}

	if (!(netdev->flags & IFF_PROMISC) &&
	    test_and_clear_bit(__IDPF_PROMISC_UC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Leaving promiscuous mode\n");
	}

	if (netdev->flags & IFF_ALLMULTI &&
	    !test_and_set_bit(__IDPF_PROMISC_MC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Entering multicast promiscuous mode\n");
	}

	if (!(netdev->flags & (IFF_ALLMULTI | IFF_PROMISC)) &&
	    test_and_clear_bit(__IDPF_PROMISC_MC, config_data->user_flags)) {
		changed = true;
		dev_info(dev, "Leaving multicast promiscuous mode\n");
	}

	if (!changed)
		return;

	err = idpf_set_promiscuous(adapter, config_data, np->vport_id);
	if (err)
		dev_err(dev, "Failed to set promiscuous mode: %d\n", err);
}

/**
 * idpf_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int idpf_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	netdev_features_t changed = netdev->features ^ features;
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_eth_adapter *adapter;
	struct idpf_vport *vport;
	struct device *dev;
	int err = 0;

	idpf_vport_ctrl_lock(netdev);

	adapter = np->adapter;
	dev = idpf_adapter_to_pdev_dev(adapter);
	if (test_bit(IDPF_ETH_RESET_IN_PROG, adapter->flags)) {
		dev_err(dev,
			"Device is resetting, changing netdev features temporarily unavailable.\n");
		err = -EBUSY;
		goto unlock_mutex;
	}

	vport = idpf_netdev_to_vport(netdev);
	if (changed & NETIF_F_RXHASH) {
		netdev->features ^= NETIF_F_RXHASH;
		err = idpf_vport_manage_rss_lut(vport);
		if (err)
			goto unlock_mutex;
	}

	if (changed & NETIF_F_GRO_HW) {
		netdev->features ^= NETIF_F_GRO_HW;
		err = idpf_initiate_soft_reset(vport, IDPF_SR_RSC_CHANGE);
		if (err)
			goto unlock_mutex;
	}

	if (changed & NETIF_F_LOOPBACK) {
		netdev->features ^= NETIF_F_LOOPBACK;
		err = idpf_send_ena_dis_loopback_msg(vport);
	}

unlock_mutex:
	idpf_vport_ctrl_unlock(netdev);

	return err;
}

/**
 * idpf_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
static int idpf_open(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport;
	int err = 0;

	idpf_vport_ctrl_lock(netdev);
	
	if (test_bit(IDPF_ETH_RESET_IN_PROG, np->adapter->flags))
		goto unlock_mutex;

	vport = idpf_netdev_to_vport(netdev);
	err = idpf_vport_open(vport, true);

unlock_mutex:
	idpf_vport_ctrl_unlock(netdev);
	return err;
}

/**
 * idpf_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport;
	int err;

	idpf_vport_ctrl_lock(netdev);

	if (test_bit(IDPF_ETH_RESET_IN_PROG, np->adapter->flags)) {
		err = -EBUSY; /* Temporarily busy indication */
		goto unlock_mutex;
	}

	vport = idpf_netdev_to_vport(netdev);
	netdev->mtu = new_mtu;

	err = idpf_initiate_soft_reset(vport, IDPF_SR_MTU_CHANGE);

unlock_mutex:
	idpf_vport_ctrl_unlock(netdev);
	return err;
}

/**
 * idpf_features_check - Validate packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t idpf_features_check(struct sk_buff *skb,
					     struct net_device *netdev,
					     netdev_features_t features)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_eth_adapter *adapter = vport->adapter;
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame.  We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 88 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) &&
	    (skb_shinfo(skb)->gso_size < IDPF_TX_TSO_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	/* Ensure MACLEN is <= 126 bytes (63 words) and not an odd size */
	len = skb_network_offset(skb);
	if (unlikely(len & ~(126)))
		goto unsupported;

	len = skb_network_header_len(skb);
	if (unlikely(len > idpf_eth_get_max_tx_hdr_size(adapter)))
		goto unsupported;

	if (!skb->encapsulation)
		return features;

	/* L4TUNLEN can support 127 words */
	len = skb_inner_network_header(skb) - skb_transport_header(skb);
	if (unlikely(len & ~(127 * 2)))
		goto unsupported;

	/* IPLEN can support at most 127 dwords */
	len = skb_inner_network_header_len(skb);
	if (unlikely(len > idpf_eth_get_max_tx_hdr_size(adapter)))
		goto unsupported;

	/* No need to validate L4LEN as TCP is the only protocol with a
	 * a flexible value and we support all possible values supported
	 * by TCP, which is at most 15 dwords
	 */

	return features;

unsupported:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

/**
 * idpf_set_mac - NDO callback to set port mac address
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int idpf_set_mac(struct net_device *netdev, void *p)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_eth_idc_auxiliary_dev_caps *caps;
	struct idpf_vport_config *vport_config;
	struct sockaddr *addr = p;
	struct idpf_vport *vport;
	struct device *dev;
	int err = 0;

	idpf_vport_ctrl_lock(netdev);

	if (test_bit(IDPF_ETH_RESET_IN_PROG, np->adapter->flags)) {
		err = -EBUSY; /* Temporarily busy indication */
		goto unlock_mutex;
	}

	vport = idpf_netdev_to_vport(netdev);
	dev = idpf_adapter_to_pdev_dev(vport->adapter);
	caps = idpf_eth_caps(vport->adapter);

	if (!idpf_is_cap_ena(caps, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_info(dev, "Setting MAC address is not supported\n");
		err = -EOPNOTSUPP;
		goto unlock_mutex;
	}

	if (!is_valid_ether_addr(addr->sa_data)) {
		dev_info(dev, "Invalid MAC address: %pM\n",
			 addr->sa_data);
		err = -EADDRNOTAVAIL;
		goto unlock_mutex;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data))
		goto unlock_mutex;

	vport_config = vport->adapter->vport_config;
	err = idpf_add_mac_filter(vport, np, addr->sa_data, false);
	if (err) {
		__idpf_del_mac_filter(vport_config, addr->sa_data);
		goto unlock_mutex;
	}

	if (is_valid_ether_addr(vport->default_mac_addr))
		idpf_del_mac_filter(vport, np, vport->default_mac_addr, false);

	ether_addr_copy(vport->default_mac_addr, addr->sa_data);
	eth_hw_addr_set(netdev, addr->sa_data);

unlock_mutex:
	idpf_vport_ctrl_unlock(netdev);

	return err;
}

static const struct net_device_ops idpf_netdev_ops_splitq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_splitq_start,
	.ndo_features_check = idpf_features_check,
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
	.ndo_change_mtu = idpf_change_mtu,
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
};

static const struct net_device_ops idpf_netdev_ops_singleq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_singleq_start,
	.ndo_features_check = idpf_features_check,
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
	.ndo_change_mtu = idpf_change_mtu,
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
};
