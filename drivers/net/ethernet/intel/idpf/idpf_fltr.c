// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include "idpf.h"
#include "idpf_virtchnl.h"
#include "idpf_fltr.h"

/**
 * idpf_find_mac_filter - Search filter list for specific mac filter
 * @vconfig: Vport config structure
 * @macaddr: The MAC address
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_filter_list_lock.
 **/
static
struct idpf_mac_filter *idpf_find_mac_filter(struct idpf_vport_config *vconfig,
					     const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	if (!macaddr)
		return NULL;

	list_for_each_entry(f, &vconfig->user_config.mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}

	return NULL;
}

/**
 * __idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport_config: Vport config structure
 * @macaddr: The MAC address
 *
 * Returns 0 on success, error value on failure
 **/
int __idpf_del_mac_filter(struct idpf_vport_config *vport_config,
			  const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	spin_lock_bh(&vport_config->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	return 0;
}

/**
 * idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: Main vport structure
 * @np: Netdev private structure
 * @macaddr: The MAC address
 * @async: Don't wait for return message
 *
 * Removes filter from list and if interface is up, tells hardware about the
 * removed filter.
 **/
int idpf_del_mac_filter(struct idpf_vport *vport,
			struct idpf_netdev_priv *np,
			const u8 *macaddr, bool async)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = np->adapter->vport_config[np->vport_idx];

	spin_lock_bh(&vport_config->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		f->remove = true;
	} else {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return -EINVAL;
	}
	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	if (np->state == __IDPF_VPORT_UP) {
		int err;

		err = idpf_add_del_mac_filters(vport, np, false, async);
		if (err)
			return err;
	}

	return  __idpf_del_mac_filter(vport_config, macaddr);
}

/**
 * __idpf_add_mac_filter - Add mac filter helper function
 * @vport_config: Vport config structure
 * @macaddr: Address to add
 *
 * Takes mac_filter_list_lock spinlock to add new filter to list.
 */
static int __idpf_add_mac_filter(struct idpf_vport_config *vport_config,
				 const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	spin_lock_bh(&vport_config->mac_filter_list_lock);

	f = idpf_find_mac_filter(vport_config, macaddr);
	if (f) {
		f->remove = false;
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return 0;
	}

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return -ENOMEM;
	}

	ether_addr_copy(f->macaddr, macaddr);
	list_add_tail(&f->list, &vport_config->user_config.mac_filter_list);
	f->add = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	return 0;
}

/**
 * idpf_add_mac_filter - Add a mac filter to the filter list
 * @vport: Main vport structure
 * @np: Netdev private structure
 * @macaddr: The MAC address
 * @async: Don't wait for return message
 *
 * Returns 0 on success or error on failure. If interface is up, we'll also
 * send the virtchnl message to tell hardware about the filter.
 **/
int idpf_add_mac_filter(struct idpf_vport *vport,
			struct idpf_netdev_priv *np,
			const u8 *macaddr, bool async)
{
	struct idpf_vport_config *vport_config;
	int err;

	vport_config = np->adapter->vport_config[np->vport_idx];
	err = __idpf_add_mac_filter(vport_config, macaddr);
	if (err)
		return err;

	if (np->state == __IDPF_VPORT_UP)
		err = idpf_add_del_mac_filters(vport, np, true, async);

	return err;
}

/**
 * idpf_del_all_mac_filters - Delete all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Deletes all filters
 */
void idpf_del_all_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f, *ftmp;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry_safe(f, ftmp,
				 &vport_config->user_config.mac_filter_list,
				 list) {
		list_del(&f->list);
		kfree(f);
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);
}

/**
 * idpf_restore_mac_filters - Re-add all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets add field to true for filters to
 * resync filters back to HW.
 */
void idpf_restore_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->add = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, netdev_priv(vport->netdev),
				 true, false);
}

/**
 * idpf_remove_mac_filters - Remove all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock. Sets remove field to true for filters
 * to remove filters in HW.
 */
void idpf_remove_mac_filters(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->remove = true;

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, netdev_priv(vport->netdev),
				 false, false);
}

/**
 * idpf_deinit_mac_addr - deinitialize mac address for vport
 * @vport: main vport structure
 */
void idpf_deinit_mac_addr(struct idpf_vport *vport)
{
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = vport->adapter->vport_config[vport->idx];

	spin_lock_bh(&vport_config->mac_filter_list_lock);

	f = idpf_find_mac_filter(vport_config, vport->default_mac_addr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);
}

/**
 * idpf_init_mac_addr - initialize mac address for vport
 * @vport: main vport structure
 * @netdev: pointer to netdev struct associated with this vport
 */
int idpf_init_mac_addr(struct idpf_vport *vport,
		       struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_adapter *adapter = vport->adapter;
	int err;

	if (is_valid_ether_addr(vport->default_mac_addr)) {
		eth_hw_addr_set(netdev, vport->default_mac_addr);
		ether_addr_copy(netdev->perm_addr, vport->default_mac_addr);

		return idpf_add_mac_filter(vport, np, vport->default_mac_addr,
					   false);
	}

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_err(&adapter->pdev->dev,
			"MAC address is not provided and capability is not set\n");

		return -EINVAL;
	}

	eth_hw_addr_random(netdev);
	err = idpf_add_mac_filter(vport, np, netdev->dev_addr, false);
	if (err)
		return err;

	dev_info(&adapter->pdev->dev, "Invalid MAC address %pM, using random %pM\n",
		 vport->default_mac_addr, netdev->dev_addr);
	ether_addr_copy(vport->default_mac_addr, netdev->dev_addr);

	return 0;
}

/**
 * idpf_mac_filter_async_handler - Async callback for mac filters
 * @adapter: private data struct
 * @xn: transaction for message
 * @ctlq_msg: received message
 *
 * In some scenarios driver can't sleep and wait for a reply (e.g.: stack is
 * holding rtnl_lock) when adding a new mac filter. It puts us in a difficult
 * situation to deal with errors returned on the reply. The best we can
 * ultimately do is remove it from our list of mac filters and report the
 * error.
 */
static int idpf_mac_filter_async_handler(struct idpf_adapter *adapter,
					 struct idpf_vc_xn *xn,
					 const struct idpf_ctlq_msg *ctlq_msg)
{
	struct virtchnl2_mac_addr_list *ma_list;
	struct idpf_vport_config *vport_config;
	struct virtchnl2_mac_addr *mac_addr;
	struct idpf_mac_filter *f, *tmp;
	struct list_head *ma_list_head;
	struct idpf_vport *vport;
	u16 num_entries;
	int i;

	/* if success we're done, we're only here if something bad happened */
	if (!ctlq_msg->cookie.mbx.chnl_retval)
		return 0;

	/* make sure at least struct is there */
	if (xn->reply_sz < sizeof(*ma_list))
		goto invalid_payload;

	ma_list = ctlq_msg->ctx.indirect.payload->va;
	mac_addr = ma_list->mac_addr_list;
	num_entries = le16_to_cpu(ma_list->num_mac_addr);
	/* we should have received a buffer at least this big */
	if (xn->reply_sz < struct_size(ma_list, mac_addr_list, num_entries))
		goto invalid_payload;

	vport = idpf_vid_to_vport(adapter, le32_to_cpu(ma_list->vport_id));
	if (!vport)
		goto invalid_payload;

	vport_config = adapter->vport_config[le32_to_cpu(ma_list->vport_id)];
	ma_list_head = &vport_config->user_config.mac_filter_list;

	/* We can't do much to reconcile bad filters at this point, however we
	 * should at least remove them from our list one way or the other so we
	 * have some idea what good filters we have.
	 */
	spin_lock_bh(&vport_config->mac_filter_list_lock);
	list_for_each_entry_safe(f, tmp, ma_list_head, list)
		for (i = 0; i < num_entries; i++)
			if (ether_addr_equal(mac_addr[i].addr, f->macaddr))
				list_del(&f->list);
	spin_unlock_bh(&vport_config->mac_filter_list_lock);
	dev_err_ratelimited(&adapter->pdev->dev, "Received error sending MAC filter request (op %d)\n",
			    xn->vc_op);

	return 0;

invalid_payload:
	dev_err_ratelimited(&adapter->pdev->dev, "Received invalid MAC filter payload (op %d) (len %zd)\n",
			    xn->vc_op, xn->reply_sz);

	return -EINVAL;
}

/**
 * idpf_add_del_mac_filters - Add/del mac filters
 * @vport: Virtual port data structure
 * @np: Netdev private structure
 * @add: Add or delete flag
 * @async: Don't wait for return message
 *
 * Returns 0 on success, error on failure.
 **/
int idpf_add_del_mac_filters(struct idpf_vport *vport,
			     struct idpf_netdev_priv *np,
			     bool add, bool async)
{
	struct virtchnl2_mac_addr_list *ma_list __free(kfree) = NULL;
	struct virtchnl2_mac_addr *mac_addr __free(kfree) = NULL;
	struct idpf_adapter *adapter = np->adapter;
	struct idpf_vc_xn_params xn_params = {};
	struct idpf_vport_config *vport_config;
	u32 num_msgs, total_filters = 0;
	struct idpf_mac_filter *f;
	ssize_t reply_sz;
	int i = 0, k;

	xn_params.vc_op = add ? VIRTCHNL2_OP_ADD_MAC_ADDR :
				VIRTCHNL2_OP_DEL_MAC_ADDR;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.async = async;
	xn_params.async_handler = idpf_mac_filter_async_handler;

	vport_config = adapter->vport_config[np->vport_idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	/* Find the number of newly added filters */
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list,
			    list) {
		if (add && f->add)
			total_filters++;
		else if (!add && f->remove)
			total_filters++;
	}

	if (!total_filters) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return 0;
	}

	/* Fill all the new filters into virtchannel message */
	mac_addr = kcalloc(total_filters, sizeof(struct virtchnl2_mac_addr),
			   GFP_ATOMIC);
	if (!mac_addr) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return -ENOMEM;
	}

	list_for_each_entry(f, &vport_config->user_config.mac_filter_list,
			    list) {
		if (add && f->add) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->add = false;
			if (i == total_filters)
				break;
		}
		if (!add && f->remove) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->remove = false;
			if (i == total_filters)
				break;
		}
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	/* Chunk up the filters into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	num_msgs = DIV_ROUND_UP(total_filters, IDPF_NUM_FILTERS_PER_MSG);

	for (i = 0, k = 0; i < num_msgs; i++) {
		u32 entries_size, buf_size, num_entries;

		num_entries = min_t(u32, total_filters,
				    IDPF_NUM_FILTERS_PER_MSG);
		entries_size = sizeof(struct virtchnl2_mac_addr) * num_entries;
		buf_size = struct_size(ma_list, mac_addr_list, num_entries);

		if (!ma_list || num_entries != IDPF_NUM_FILTERS_PER_MSG) {
			kfree(ma_list);
			ma_list = kzalloc(buf_size, GFP_ATOMIC);
			if (!ma_list)
				return -ENOMEM;
		} else {
			memset(ma_list, 0, buf_size);
		}

		ma_list->vport_id = cpu_to_le32(np->vport_id);
		ma_list->num_mac_addr = cpu_to_le16(num_entries);
		memcpy(ma_list->mac_addr_list, &mac_addr[k], entries_size);

		xn_params.send_buf.iov_base = ma_list;
		xn_params.send_buf.iov_len = buf_size;
		reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		k += num_entries;
		total_filters -= num_entries;
	}

	return 0;
}

/**
 * idpf_set_promiscuous - set promiscuous and send message to mailbox
 * @adapter: Driver specific private structure
 * @config_data: Vport specific config data
 * @vport_id: Vport identifier
 *
 * Request to enable promiscuous mode for the vport. Message is sent
 * asynchronously and won't wait for response.  Returns 0 on success, negative
 * on failure;
 */
int idpf_set_promiscuous(struct idpf_adapter *adapter,
			 struct idpf_vport_user_config_data *config_data,
			 u32 vport_id)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_promisc_info vpi;
	ssize_t reply_sz;
	u16 flags = 0;

	if (test_bit(__IDPF_PROMISC_UC, config_data->user_flags))
		flags |= VIRTCHNL2_UNICAST_PROMISC;
	if (test_bit(__IDPF_PROMISC_MC, config_data->user_flags))
		flags |= VIRTCHNL2_MULTICAST_PROMISC;

	vpi.vport_id = cpu_to_le32(vport_id);
	vpi.flags = cpu_to_le16(flags);

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &vpi;
	xn_params.send_buf.iov_len = sizeof(vpi);
	/* setting promiscuous is only ever done asynchronously */
	xn_params.async = true;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}
