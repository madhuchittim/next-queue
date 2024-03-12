// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include "idpf.h"
#include "idpf_virtchnl.h"
#include "idpf_netdev.h"
#include "idpf_fltr.h"

/**
 * idpf_vid_to_vport - Translate vport id to vport pointer
 * @adapter: private data struct
 * @v_id: vport id to translate
 *
 * Returns vport matching v_id, NULL if not found.
 */
struct idpf_vport *idpf_vid_to_vport(struct idpf_adapter *adapter, u32 v_id)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);
	int i;

	for (i = 0; i < num_max_vports; i++)
		if (adapter->vport_ids[i] == v_id)
			return adapter->vports[i];

	return NULL;
}

/**
 * idpf_handle_event_link - Handle link event message
 * @adapter: private data struct
 * @v2e: virtchnl event message
 */
void idpf_handle_event_link(struct idpf_adapter *adapter,
			    const struct virtchnl2_event *v2e)
{
	struct idpf_netdev_priv *np;
	struct idpf_vport *vport;

	vport = idpf_vid_to_vport(adapter, le32_to_cpu(v2e->vport_id));
	if (!vport) {
		dev_err_ratelimited(&adapter->pdev->dev, "Failed to find vport_id %d for link event\n",
				    v2e->vport_id);
		return;
	}
	np = netdev_priv(vport->netdev);

	vport->link_speed_mbps = le32_to_cpu(v2e->link_speed);

	if (vport->link_up == v2e->link_status)
		return;

	vport->link_up = v2e->link_status;

	if (np->state != __IDPF_VPORT_UP)
		return;

	if (vport->link_up) {
		netif_tx_start_all_queues(vport->netdev);
		netif_carrier_on(vport->netdev);
	} else {
		netif_tx_stop_all_queues(vport->netdev);
		netif_carrier_off(vport->netdev);
	}
}

/**
 * idpf_get_free_slot - get the next non-NULL location index in array
 * @adapter: adapter in which to look for a free vport slot
 */
static int idpf_get_free_slot(struct idpf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->max_vports; i++) {
		if (!adapter->vports[i])
			return i;
	}

	return IDPF_NO_FREE_SLOT;
}

/**
 * idpf_remove_features - Turn off feature configs
 * @vport: virtual port structure
 */
static void idpf_remove_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_remove_mac_filters(vport);
}

/**
 * idpf_vport_stop - Disable a vport
 * @vport: vport to disable
 */
void idpf_vport_stop(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);

	if (np->state <= __IDPF_VPORT_DOWN)
		return;

	netif_carrier_off(vport->netdev);
	netif_tx_disable(vport->netdev);

	idpf_send_disable_vport_msg(vport);
	idpf_send_disable_queues_msg(vport);
	idpf_send_map_unmap_queue_vector_msg(vport, false);
	/* Normally we ask for queues in create_vport, but if the number of
	 * initially requested queues have changed, for example via ethtool
	 * set channels, we do delete queues and then add the queues back
	 * instead of deleting and reallocating the vport.
	 */
	if (test_and_clear_bit(IDPF_VPORT_DEL_QUEUES, vport->flags))
		idpf_send_delete_queues_msg(vport);

	idpf_remove_features(vport);

	vport->link_up = false;
	idpf_vport_intr_deinit(vport);
	idpf_vport_intr_rel(vport);
	idpf_vport_queues_rel(vport);
	np->state = __IDPF_VPORT_DOWN;
}

/**
 * idpf_vport_rel - Delete a vport and free its resources
 * @vport: the vport being removed
 */
void idpf_vport_rel(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_vector_info vec_info;
	struct idpf_rss_data *rss_data;
	struct idpf_vport_max_q max_q;
	u16 idx = vport->idx;

	vport_config = adapter->vport_config[vport->idx];
	idpf_deinit_rss(vport);
	rss_data = &vport_config->user_config.rss_data;
	kfree(rss_data->rss_key);
	rss_data->rss_key = NULL;

	idpf_send_destroy_vport_msg(vport);

	/* Release all max queues allocated to the adapter's pool */
	max_q.max_rxq = vport_config->max_q.max_rxq;
	max_q.max_txq = vport_config->max_q.max_txq;
	max_q.max_bufq = vport_config->max_q.max_bufq;
	max_q.max_complq = vport_config->max_q.max_complq;
	idpf_vport_dealloc_max_qs(adapter, &max_q);

	/* Release all the allocated vectors on the stack */
	vec_info.num_req_vecs = 0;
	vec_info.num_curr_vecs = vport->num_q_vectors;
	vec_info.default_vport = vport->default_vport;

	idpf_req_rel_vector_indexes(adapter, vport->q_vector_idxs, &vec_info);

	kfree(vport->q_vector_idxs);
	vport->q_vector_idxs = NULL;

	kfree(adapter->vport_params_recvd[idx]);
	adapter->vport_params_recvd[idx] = NULL;
	kfree(adapter->vport_params_reqd[idx]);
	adapter->vport_params_reqd[idx] = NULL;
	if (adapter->vport_config[idx]) {
		kfree(adapter->vport_config[idx]->req_qs_chunks);
		adapter->vport_config[idx]->req_qs_chunks = NULL;
	}
	kfree(vport);
	adapter->num_alloc_vports--;
}

/**
 * idpf_vport_dealloc - cleanup and release a given vport
 * @vport: pointer to idpf vport structure
 *
 * returns nothing
 */
void idpf_vport_dealloc(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	unsigned int i = vport->idx;

	idpf_deinit_mac_addr(vport);
	idpf_vport_stop(vport);

	if (!test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags))
		idpf_decfg_netdev(vport);
	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		idpf_del_all_mac_filters(vport);

	if (adapter->netdevs[i]) {
		struct idpf_netdev_priv *np = netdev_priv(adapter->netdevs[i]);

		np->vport = NULL;
	}

	idpf_vport_rel(vport);

	adapter->vports[i] = NULL;
	adapter->next_vport = idpf_get_free_slot(adapter);
}

/**
 * idpf_is_hsplit_supported - check whether the header split is supported
 * @vport: virtual port to check the capability for
 *
 * Return: true if it's supported by the HW/FW, false if not.
 */
static bool idpf_is_hsplit_supported(const struct idpf_vport *vport)
{
	return idpf_is_queue_model_split(vport->rxq_model) &&
	       idpf_is_cap_ena_all(vport->adapter, IDPF_HSPLIT_CAPS,
				   IDPF_CAP_HSPLIT);
}

/**
 * idpf_vport_get_hsplit - get the current header split feature state
 * @vport: virtual port to query the state for
 *
 * Return: ``ETHTOOL_TCP_DATA_SPLIT_UNKNOWN`` if not supported,
 *         ``ETHTOOL_TCP_DATA_SPLIT_DISABLED`` if disabled,
 *         ``ETHTOOL_TCP_DATA_SPLIT_ENABLED`` if active.
 */
u8 idpf_vport_get_hsplit(const struct idpf_vport *vport)
{
	const struct idpf_vport_user_config_data *config;

	if (!idpf_is_hsplit_supported(vport))
		return ETHTOOL_TCP_DATA_SPLIT_UNKNOWN;

	config = &vport->adapter->vport_config[vport->idx]->user_config;

	return test_bit(__IDPF_USER_FLAG_HSPLIT, config->user_flags) ?
	       ETHTOOL_TCP_DATA_SPLIT_ENABLED :
	       ETHTOOL_TCP_DATA_SPLIT_DISABLED;
}

/**
 * idpf_vport_set_hsplit - enable or disable header split on a given vport
 * @vport: virtual port to configure
 * @val: Ethtool flag controlling the header split state
 *
 * Return: true on success, false if not supported by the HW.
 */
bool idpf_vport_set_hsplit(const struct idpf_vport *vport, u8 val)
{
	struct idpf_vport_user_config_data *config;

	if (!idpf_is_hsplit_supported(vport))
		return val == ETHTOOL_TCP_DATA_SPLIT_UNKNOWN;

	config = &vport->adapter->vport_config[vport->idx]->user_config;

	switch (val) {
	case ETHTOOL_TCP_DATA_SPLIT_UNKNOWN:
		/* Default is to enable */
	case ETHTOOL_TCP_DATA_SPLIT_ENABLED:
		__set_bit(__IDPF_USER_FLAG_HSPLIT, config->user_flags);
		return true;
	case ETHTOOL_TCP_DATA_SPLIT_DISABLED:
		__clear_bit(__IDPF_USER_FLAG_HSPLIT, config->user_flags);
		return true;
	default:
		return false;
	}
}

/**
 * idpf_vport_alloc - Allocates the next available struct vport in the adapter
 * @adapter: board private structure
 * @max_q: vport max queue info
 *
 * returns a pointer to a vport on success, NULL on failure.
 */
struct idpf_vport *idpf_vport_alloc(struct idpf_adapter *adapter,
				    struct idpf_vport_max_q *max_q)
{
	struct idpf_rss_data *rss_data;
	u16 idx = adapter->next_vport;
	struct idpf_vport *vport;
	u16 num_max_q;

	if (idx == IDPF_NO_FREE_SLOT)
		return NULL;

	vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!vport)
		return vport;

	if (!adapter->vport_config[idx]) {
		struct idpf_vport_config *vport_config;

		vport_config = kzalloc(sizeof(*vport_config), GFP_KERNEL);
		if (!vport_config) {
			kfree(vport);

			return NULL;
		}

		adapter->vport_config[idx] = vport_config;
	}

	vport->idx = idx;
	vport->adapter = adapter;
	vport->compln_clean_budget = IDPF_TX_COMPLQ_CLEAN_BUDGET;
	vport->default_vport = adapter->num_alloc_vports <
			       idpf_get_default_vports(adapter);

	num_max_q = max(max_q->max_txq, max_q->max_rxq);
	vport->q_vector_idxs = kcalloc(num_max_q, sizeof(u16), GFP_KERNEL);
	if (!vport->q_vector_idxs) {
		kfree(vport);

		return NULL;
	}
	idpf_vport_init(vport, max_q);

	/* This alloc is done separate from the LUT because it's not strictly
	 * dependent on how many queues we have. If we change number of queues
	 * and soft reset we'll need a new LUT but the key can remain the same
	 * for as long as the vport exists.
	 */
	rss_data = &adapter->vport_config[idx]->user_config.rss_data;
	rss_data->rss_key = kzalloc(rss_data->rss_key_size, GFP_KERNEL);
	if (!rss_data->rss_key) {
		kfree(vport);

		return NULL;
	}
	/* Initialize default rss key */
	netdev_rss_key_fill((void *)rss_data->rss_key, rss_data->rss_key_size);

	/* fill vport slot in the adapter struct */
	adapter->vports[idx] = vport;
	adapter->vport_ids[idx] = idpf_get_vport_id(vport);

	adapter->num_alloc_vports++;
	/* prepare adapter->next_vport for next use */
	adapter->next_vport = idpf_get_free_slot(adapter);

	return vport;
}

/**
 * idpf_vport_alloc_vec_indexes - Get relative vector indexes
 * @vport: virtual port data struct
 *
 * This function requests the vector information required for the vport and
 * stores the vector indexes received from the 'global vector distribution'
 * in the vport's queue vectors array.
 *
 * Return 0 on success, error on failure
 */
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport)
{
	struct idpf_vector_info vec_info;
	int num_alloc_vecs;

	vec_info.num_curr_vecs = vport->num_q_vectors;
	vec_info.num_req_vecs = max(vport->num_txq, vport->num_rxq);
	vec_info.default_vport = vport->default_vport;
	vec_info.index = vport->idx;

	num_alloc_vecs = idpf_req_rel_vector_indexes(vport->adapter,
						     vport->q_vector_idxs,
						     &vec_info);
	if (num_alloc_vecs <= 0) {
		dev_err(&vport->adapter->pdev->dev, "Vector distribution failed: %d\n",
			num_alloc_vecs);
		return -EINVAL;
	}

	vport->num_q_vectors = num_alloc_vecs;

	return 0;
}

/**
 * idpf_vport_init - Initialize virtual port
 * @vport: virtual port to be initialized
 * @max_q: vport max queue info
 *
 * Will initialize vport with the info received through MB earlier
 */
void idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vport_config *vport_config;
	u16 tx_itr[] = {2, 8, 64, 128, 256};
	u16 rx_itr[] = {2, 8, 32, 96, 128};
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;

	vport_config = adapter->vport_config[idx];
	rss_data = &vport_config->user_config.rss_data;
	vport_msg = adapter->vport_params_recvd[idx];

	vport_config->max_q.max_txq = max_q->max_txq;
	vport_config->max_q.max_rxq = max_q->max_rxq;
	vport_config->max_q.max_complq = max_q->max_complq;
	vport_config->max_q.max_bufq = max_q->max_bufq;

	vport->txq_model = le16_to_cpu(vport_msg->txq_model);
	vport->rxq_model = le16_to_cpu(vport_msg->rxq_model);
	vport->vport_type = le16_to_cpu(vport_msg->vport_type);
	vport->vport_id = le32_to_cpu(vport_msg->vport_id);

	rss_data->rss_key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
				       le16_to_cpu(vport_msg->rss_key_size));
	rss_data->rss_lut_size = le16_to_cpu(vport_msg->rss_lut_size);

	ether_addr_copy(vport->default_mac_addr, vport_msg->default_mac_addr);
	vport->max_mtu = le16_to_cpu(vport_msg->max_mtu) - IDPF_PACKET_HDR_PAD;

	/* Initialize Tx and Rx profiles for Dynamic Interrupt Moderation */
	memcpy(vport->rx_itr_profile, rx_itr, IDPF_DIM_PROFILE_SLOTS);
	memcpy(vport->tx_itr_profile, tx_itr, IDPF_DIM_PROFILE_SLOTS);

	idpf_vport_set_hsplit(vport, ETHTOOL_TCP_DATA_SPLIT_ENABLED);

	idpf_vport_init_num_qs(vport, vport_msg);
	idpf_vport_calc_num_q_desc(vport);
	idpf_vport_calc_num_q_groups(vport);
	idpf_vport_alloc_vec_indexes(vport);

	vport->crc_enable = adapter->crc_enable;
}

/**
 * idpf_vport_get_q_reg - Get the queue registers for the vport
 * @reg_vals: register values needing to be set
 * @num_regs: amount we expect to fill
 * @q_type: queue model
 * @chunks: queue regs received over mailbox
 *
 * This function parses the queue register offsets from the queue register
 * chunk information, with a specific queue type and stores it into the array
 * passed as an argument. It returns the actual number of queue registers that
 * are filled.
 */
static int idpf_vport_get_q_reg(u32 *reg_vals, int num_regs, u32 q_type,
				struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	int reg_filled = 0, i;
	u32 reg_val;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;
		u16 num_q;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		reg_val = le64_to_cpu(chunk->qtail_reg_start);
		for (i = 0; i < num_q && reg_filled < num_regs ; i++) {
			reg_vals[reg_filled++] = reg_val;
			reg_val += le32_to_cpu(chunk->qtail_reg_spacing);
		}
	}

	return reg_filled;
}

/**
 * __idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 * @reg_vals: registers we are initializing
 * @num_regs: how many registers there are in total
 * @q_type: queue model
 *
 * Return number of queues that are initialized
 */
static int __idpf_queue_reg_init(struct idpf_vport *vport, u32 *reg_vals,
				 int num_regs, u32 q_type)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq && k < num_regs;
			     j++, k++)
				tx_qgrp->txqs[j]->tail =
					idpf_get_reg_addr(adapter, reg_vals[k]);
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u16 num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq && k < num_regs; j++, k++) {
				q = rx_qgrp->singleq.rxqs[j];
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u8 num_bufqs = vport->num_bufqs_per_qgrp;

			for (j = 0; j < num_bufqs && k < num_regs; j++, k++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 *
 * Return 0 on success, negative on failure
 */
int idpf_queue_reg_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int num_regs, ret = 0;
	u32 *reg_vals;

	/* We may never deal with more than 256 same type of queues */
	reg_vals = kzalloc(sizeof(void *) * IDPF_LARGE_MAX_Q, GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
		  (struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	/* Initialize Tx queue tail register address */
	num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
					VIRTCHNL2_QUEUE_TYPE_TX,
					chunks);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
					 VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	/* Initialize Rx/buffer queue tail register address based on Rx queue
	 * model
	 */
	if (idpf_is_queue_model_split(vport->rxq_model)) {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX_BUFFER,
						chunks);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX_BUFFER);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	} else {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX,
						chunks);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	}

free_reg_vals:
	kfree(reg_vals);

	return ret;
}

/**
 * idpf_restore_features - Restore feature configs
 * @vport: virtual port structure
 */
static void idpf_restore_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_restore_mac_filters(vport);
}

/**
 * idpf_set_real_num_queues - set number of queues for netdev
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_set_real_num_queues(struct idpf_vport *vport)
{
	int err;

	err = netif_set_real_num_rx_queues(vport->netdev, vport->num_rxq);
	if (err)
		return err;

	return netif_set_real_num_tx_queues(vport->netdev, vport->num_txq);
}

/**
 * idpf_up_complete - Complete interface up sequence
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_up_complete(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);

	if (vport->link_up && !netif_carrier_ok(vport->netdev)) {
		netif_carrier_on(vport->netdev);
		netif_tx_start_all_queues(vport->netdev);
	}

	np->state = __IDPF_VPORT_UP;

	return 0;
}

/**
 * idpf_rx_init_buf_tail - Write initial buffer ring tail value
 * @vport: virtual port struct
 */
static void idpf_rx_init_buf_tail(struct idpf_vport *vport)
{
	int i, j;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *grp = &vport->rxq_grps[i];

		if (idpf_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				struct idpf_queue *q =
					&grp->splitq.bufq_sets[j].bufq;

				writel(q->next_to_alloc, q->tail);
			}
		} else {
			for (j = 0; j < grp->singleq.num_rxq; j++) {
				struct idpf_queue *q =
					grp->singleq.rxqs[j];

				writel(q->next_to_alloc, q->tail);
			}
		}
	}
}

/**
 * idpf_set_vport_state - Set the vport state to be after the reset
 * @adapter: Driver specific private structure
 */
void idpf_set_vport_state(struct idpf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < adapter->max_vports; i++) {
		struct idpf_netdev_priv *np;

		if (!adapter->netdevs[i])
			continue;

		np = netdev_priv(adapter->netdevs[i]);
		if (np->state == __IDPF_VPORT_UP)
			set_bit(IDPF_VPORT_UP_REQUESTED,
				adapter->vport_config[i]->flags);
	}
}

/**
 * idpf_vport_open - Bring up a vport
 * @vport: vport to bring up
 * @alloc_res: allocate queue resources
 */
int idpf_vport_open(struct idpf_vport *vport, bool alloc_res)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	int err;

	if (np->state != __IDPF_VPORT_DOWN)
		return -EBUSY;

	/* we do not allow interface up just yet */
	netif_carrier_off(vport->netdev);

	if (alloc_res) {
		err = idpf_vport_queues_alloc(vport);
		if (err)
			return err;
	}

	err = idpf_vport_intr_alloc(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to allocate interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto queues_rel;
	}

	err = idpf_vport_queue_ids_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize queue ids for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	err = idpf_vport_intr_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize interrupts for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	err = idpf_rx_bufs_init_all(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize RX buffers for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	err = idpf_queue_reg_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize queue registers for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_rel;
	}

	idpf_rx_init_buf_tail(vport);

	err = idpf_send_config_queues_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to configure queues for vport %u, %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_map_unmap_queue_vector_msg(vport, true);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to map queue vectors for vport %u: %d\n",
			vport->vport_id, err);
		goto intr_deinit;
	}

	err = idpf_send_enable_queues_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to enable queues for vport %u: %d\n",
			vport->vport_id, err);
		goto unmap_queue_vectors;
	}

	err = idpf_send_enable_vport_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to enable vport %u: %d\n",
			vport->vport_id, err);
		err = -EAGAIN;
		goto disable_queues;
	}

	idpf_restore_features(vport);

	vport_config = adapter->vport_config[vport->idx];
	if (vport_config->user_config.rss_data.rss_lut)
		err = idpf_config_rss(vport);
	else
		err = idpf_init_rss(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize RSS for vport %u: %d\n",
			vport->vport_id, err);
		goto disable_vport;
	}

	err = idpf_up_complete(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to complete interface up for vport %u: %d\n",
			vport->vport_id, err);
		goto deinit_rss;
	}

	return 0;

deinit_rss:
	idpf_deinit_rss(vport);
disable_vport:
	idpf_send_disable_vport_msg(vport);
disable_queues:
	idpf_send_disable_queues_msg(vport);
unmap_queue_vectors:
	idpf_send_map_unmap_queue_vector_msg(vport, false);
intr_deinit:
	idpf_vport_intr_deinit(vport);
intr_rel:
	idpf_vport_intr_rel(vport);
queues_rel:
	idpf_vport_queues_rel(vport);

	return err;
}

/**
 * idpf_initiate_soft_reset - Initiate a software reset
 * @vport: virtual port data struct
 * @reset_cause: reason for the soft reset
 *
 * Soft reset only reallocs vport queue resources. Returns 0 on success,
 * negative on failure.
 */
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_reset_cause reset_cause)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	enum idpf_vport_state current_state = np->state;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport *new_vport;
	int err, i;

	/* If the system is low on memory, we can end up in bad state if we
	 * free all the memory for queue resources and try to allocate them
	 * again. Instead, we can pre-allocate the new resources before doing
	 * anything and bailing if the alloc fails.
	 *
	 * Make a clone of the existing vport to mimic its current
	 * configuration, then modify the new structure with any requested
	 * changes. Once the allocation of the new resources is done, stop the
	 * existing vport and copy the configuration to the main vport. If an
	 * error occurred, the existing vport will be untouched.
	 *
	 */
	new_vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!new_vport)
		return -ENOMEM;

	/* This purposely avoids copying the end of the struct because it
	 * contains wait_queues and mutexes and other stuff we don't want to
	 * mess with. Nothing below should use those variables from new_vport
	 * and should instead always refer to them in vport if they need to.
	 */
	memcpy(new_vport, vport, offsetof(struct idpf_vport, link_speed_mbps));

	/* Adjust resource parameters prior to reallocating resources */
	switch (reset_cause) {
	case IDPF_SR_Q_CHANGE:
		err = idpf_vport_adjust_qs(new_vport);
		if (err)
			goto free_vport;
		break;
	case IDPF_SR_Q_DESC_CHANGE:
		/* Update queue parameters before allocating resources */
		idpf_vport_calc_num_q_desc(new_vport);
		break;
	case IDPF_SR_MTU_CHANGE:
	case IDPF_SR_RSC_CHANGE:
		break;
	default:
		dev_err(&adapter->pdev->dev, "Unhandled soft reset cause\n");
		err = -EINVAL;
		goto free_vport;
	}

	err = idpf_vport_queues_alloc(new_vport);
	if (err)
		goto free_vport;
	if (current_state <= __IDPF_VPORT_DOWN) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

	idpf_deinit_rss(vport);
	/* We're passing in vport here because we need its wait_queue
	 * to send a message and it should be getting all the vport
	 * config data out of the adapter but we need to be careful not
	 * to add code to add_queues to change the vport config within
	 * vport itself as it will be wiped with a memcpy later.
	 */
	err = idpf_send_add_queues_msg(vport, new_vport->num_txq,
				       new_vport->num_complq,
				       new_vport->num_rxq,
				       new_vport->num_bufq);
	if (err)
		goto err_reset;

	/* Same comment as above regarding avoiding copying the wait_queues and
	 * mutexes applies here. We do not want to mess with those if possible.
	 */
	memcpy(vport, new_vport, offsetof(struct idpf_vport, link_speed_mbps));

	/* Since idpf_vport_queues_alloc was called with new_port, the queue
	 * back pointers are currently pointing to the local new_vport. Reset
	 * the backpointers to the original vport here
	 */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		tx_qgrp->vport = vport;
		for (j = 0; j < tx_qgrp->num_txq; j++)
			tx_qgrp->txqs[j]->vport = vport;

		if (idpf_is_queue_model_split(vport->txq_model))
			tx_qgrp->complq->vport = vport;
	}

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		struct idpf_queue *q;
		u16 num_rxq;
		int j;

		rx_qgrp->vport = vport;
		for (j = 0; j < vport->num_bufqs_per_qgrp; j++)
			rx_qgrp->splitq.bufq_sets[j].bufq.vport = vport;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			if (idpf_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			q->vport = vport;
		}
	}

	if (reset_cause == IDPF_SR_Q_CHANGE)
		idpf_vport_alloc_vec_indexes(vport);

	err = idpf_set_real_num_queues(vport);
	if (err)
		goto err_reset;

	if (current_state == __IDPF_VPORT_UP)
		err = idpf_vport_open(vport, false);

	kfree(new_vport);

	return err;

err_reset:
	idpf_vport_queues_rel(new_vport);
free_vport:
	kfree(new_vport);

	return err;
}
