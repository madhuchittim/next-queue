// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include "idpf.h"
#include "idpf_virtchnl.h"
#include "idpf_netdev.h"
#include "idpf_fltr.h"

/**
 * idpf_wait_for_marker_event - wait for software marker response
 * @vport: virtual port data structure
 *
 * Returns 0 success, negative on failure.
 **/
static int idpf_wait_for_marker_event(struct idpf_vport *vport)
{
	int event;
	int i;

	for (i = 0; i < vport->num_txq; i++)
		set_bit(__IDPF_Q_SW_MARKER, vport->txqs[i]->flags);

	event = wait_event_timeout(vport->sw_marker_wq,
				   test_and_clear_bit(IDPF_VPORT_SW_MARKER,
						      vport->flags),
				   msecs_to_jiffies(500));

	for (i = 0; i < vport->num_txq; i++)
		clear_bit(__IDPF_Q_POLL_MODE, vport->txqs[i]->flags);

	if (event)
		return 0;

	dev_warn(&vport->adapter->pdev->dev, "Failed to receive marker packets\n");

	return -ETIMEDOUT;
}

/**
 * idpf_send_get_stats_msg - Send virtchnl get statistics message
 * @vport: vport to get stats for
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_stats_msg(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct rtnl_link_stats64 *netstats = &np->netstats;
	struct virtchnl2_vport_stats stats_msg = {};
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;

	/* Don't send get_stats message if the link is down */
	if (np->state <= __IDPF_VPORT_DOWN)
		return 0;

	stats_msg.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_GET_STATS;
	xn_params.send_buf.iov_base = &stats_msg;
	xn_params.send_buf.iov_len = sizeof(stats_msg);
	xn_params.recv_buf = xn_params.send_buf;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(stats_msg))
		return -EIO;

	spin_lock_bh(&np->stats_lock);

	netstats->rx_packets = le64_to_cpu(stats_msg.rx_unicast) +
			       le64_to_cpu(stats_msg.rx_multicast) +
			       le64_to_cpu(stats_msg.rx_broadcast);
	netstats->tx_packets = le64_to_cpu(stats_msg.tx_unicast) +
			       le64_to_cpu(stats_msg.tx_multicast) +
			       le64_to_cpu(stats_msg.tx_broadcast);
	netstats->rx_bytes = le64_to_cpu(stats_msg.rx_bytes);
	netstats->tx_bytes = le64_to_cpu(stats_msg.tx_bytes);
	netstats->rx_errors = le64_to_cpu(stats_msg.rx_errors);
	netstats->tx_errors = le64_to_cpu(stats_msg.tx_errors);
	netstats->rx_dropped = le64_to_cpu(stats_msg.rx_discards);
	netstats->tx_dropped = le64_to_cpu(stats_msg.tx_discards);

	vport->port_stats.vport_stats = stats_msg;

	spin_unlock_bh(&np->stats_lock);

	return 0;
}

/**
 * idpf_send_get_set_rss_lut_msg - Send virtchnl get or set rss lut message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport, bool get)
{
	struct virtchnl2_rss_lut *recv_rl __free(kfree) = NULL;
	struct virtchnl2_rss_lut *rl __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	struct idpf_rss_data *rss_data;
	int buf_size, lut_buf_size;
	ssize_t reply_sz;
	int i;

	rss_data =
		&vport->adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = struct_size(rl, lut, rss_data->rss_lut_size);
	rl = kzalloc(buf_size, GFP_KERNEL);
	if (!rl)
		return -ENOMEM;

	rl->vport_id = cpu_to_le32(vport->vport_id);

	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = rl;
	xn_params.send_buf.iov_len = buf_size;

	if (get) {
		recv_rl = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
		if (!recv_rl)
			return -ENOMEM;
		xn_params.vc_op = VIRTCHNL2_OP_GET_RSS_LUT;
		xn_params.recv_buf.iov_base = recv_rl;
		xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	} else {
		rl->lut_entries = cpu_to_le16(rss_data->rss_lut_size);
		for (i = 0; i < rss_data->rss_lut_size; i++)
			rl->lut[i] = cpu_to_le32(rss_data->rss_lut[i]);

		xn_params.vc_op = VIRTCHNL2_OP_SET_RSS_LUT;
	}
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (!get)
		return 0;
	if (reply_sz < sizeof(struct virtchnl2_rss_lut))
		return -EIO;

	lut_buf_size = le16_to_cpu(recv_rl->lut_entries) * sizeof(u32);
	if (reply_sz < lut_buf_size)
		return -EIO;

	/* size didn't change, we can reuse existing lut buf */
	if (rss_data->rss_lut_size == le16_to_cpu(recv_rl->lut_entries))
		goto do_memcpy;

	rss_data->rss_lut_size = le16_to_cpu(recv_rl->lut_entries);
	kfree(rss_data->rss_lut);

	rss_data->rss_lut = kzalloc(lut_buf_size, GFP_KERNEL);
	if (!rss_data->rss_lut) {
		rss_data->rss_lut_size = 0;
		return -ENOMEM;
	}

do_memcpy:
	memcpy(rss_data->rss_lut, recv_rl->lut, rss_data->rss_lut_size);

	return 0;
}

/**
 * idpf_send_get_set_rss_key_msg - Send virtchnl get or set rss key message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport, bool get)
{
	struct virtchnl2_rss_key *recv_rk __free(kfree) = NULL;
	struct virtchnl2_rss_key *rk __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	struct idpf_rss_data *rss_data;
	ssize_t reply_sz;
	int i, buf_size;
	u16 key_size;

	rss_data =
		&vport->adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = struct_size(rk, key_flex, rss_data->rss_key_size);
	rk = kzalloc(buf_size, GFP_KERNEL);
	if (!rk)
		return -ENOMEM;

	rk->vport_id = cpu_to_le32(vport->vport_id);
	xn_params.send_buf.iov_base = rk;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	if (get) {
		recv_rk = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
		if (!recv_rk)
			return -ENOMEM;

		xn_params.vc_op = VIRTCHNL2_OP_GET_RSS_KEY;
		xn_params.recv_buf.iov_base = recv_rk;
		xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	} else {
		rk->key_len = cpu_to_le16(rss_data->rss_key_size);
		for (i = 0; i < rss_data->rss_key_size; i++)
			rk->key_flex[i] = rss_data->rss_key[i];

		xn_params.vc_op = VIRTCHNL2_OP_SET_RSS_KEY;
	}

	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (!get)
		return 0;
	if (reply_sz < sizeof(struct virtchnl2_rss_key))
		return -EIO;

	key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
			 le16_to_cpu(recv_rk->key_len));
	if (reply_sz < key_size)
		return -EIO;

	/* key len didn't change, reuse existing buf */
	if (rss_data->rss_key_size == key_size)
		goto do_memcpy;

	rss_data->rss_key_size = key_size;
	kfree(rss_data->rss_key);
	rss_data->rss_key = kzalloc(key_size, GFP_KERNEL);
	if (!rss_data->rss_key) {
		rss_data->rss_key_size = 0;
		return -ENOMEM;
	}

do_memcpy:
	memcpy(rss_data->rss_key, recv_rk->key_flex, rss_data->rss_key_size);

	return 0;
}

/**
 * idpf_fill_ptype_lookup - Fill L3 specific fields in ptype lookup table
 * @ptype: ptype lookup table
 * @pstate: state machine for ptype lookup table
 * @ipv4: ipv4 or ipv6
 * @frag: fragmentation allowed
 *
 */
static void idpf_fill_ptype_lookup(struct idpf_rx_ptype_decoded *ptype,
				   struct idpf_ptype_state *pstate,
				   bool ipv4, bool frag)
{
	if (!pstate->outer_ip || !pstate->outer_frag) {
		ptype->outer_ip = IDPF_RX_PTYPE_OUTER_IP;
		pstate->outer_ip = true;

		if (ipv4)
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV4;
		else
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV6;

		if (frag) {
			ptype->outer_frag = IDPF_RX_PTYPE_FRAG;
			pstate->outer_frag = true;
		}
	} else {
		ptype->tunnel_type = IDPF_RX_PTYPE_TUNNEL_IP_IP;
		pstate->tunnel_state = IDPF_PTYPE_TUNNEL_IP;

		if (ipv4)
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV4;
		else
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV6;

		if (frag)
			ptype->tunnel_end_frag = IDPF_RX_PTYPE_FRAG;
	}
}

/**
 * idpf_send_get_rx_ptype_msg - Send virtchnl for ptype info
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport)
{
	struct virtchnl2_get_ptype_info *get_ptype_info __free(kfree) = NULL;
	struct virtchnl2_get_ptype_info *ptype_info __free(kfree) = NULL;
	struct idpf_rx_ptype_decoded *ptype_lkup = vport->rx_ptype_lkup;
	int max_ptype, ptypes_recvd = 0, ptype_offset;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vc_xn_params xn_params = {};
	u16 next_ptype_id = 0;
	ssize_t reply_sz;
	int i, j, k;

	if (idpf_is_queue_model_split(vport->rxq_model))
		max_ptype = IDPF_RX_MAX_PTYPE;
	else
		max_ptype = IDPF_RX_MAX_BASE_PTYPE;

	memset(vport->rx_ptype_lkup, 0, sizeof(vport->rx_ptype_lkup));

	get_ptype_info = kzalloc(sizeof(*get_ptype_info), GFP_KERNEL);
	if (!get_ptype_info)
		return -ENOMEM;

	ptype_info = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!ptype_info)
		return -ENOMEM;

	xn_params.vc_op = VIRTCHNL2_OP_GET_PTYPE_INFO;
	xn_params.send_buf.iov_base = get_ptype_info;
	xn_params.send_buf.iov_len = sizeof(*get_ptype_info);
	xn_params.recv_buf.iov_base = ptype_info;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	while (next_ptype_id < max_ptype) {
		get_ptype_info->start_ptype_id = cpu_to_le16(next_ptype_id);

		if ((next_ptype_id + IDPF_RX_MAX_PTYPES_PER_BUF) > max_ptype)
			get_ptype_info->num_ptypes =
				cpu_to_le16(max_ptype - next_ptype_id);
		else
			get_ptype_info->num_ptypes =
				cpu_to_le16(IDPF_RX_MAX_PTYPES_PER_BUF);

		reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		if (reply_sz < IDPF_CTLQ_MAX_BUF_LEN)
			return -EIO;

		ptypes_recvd += le16_to_cpu(ptype_info->num_ptypes);
		if (ptypes_recvd > max_ptype)
			return -EINVAL;

		next_ptype_id = le16_to_cpu(get_ptype_info->start_ptype_id) +
				le16_to_cpu(get_ptype_info->num_ptypes);

		ptype_offset = IDPF_RX_PTYPE_HDR_SZ;

		for (i = 0; i < le16_to_cpu(ptype_info->num_ptypes); i++) {
			struct idpf_ptype_state pstate = { };
			struct virtchnl2_ptype *ptype;
			u16 id;

			ptype = (struct virtchnl2_ptype *)
					((u8 *)ptype_info + ptype_offset);

			ptype_offset += IDPF_GET_PTYPE_SIZE(ptype);
			if (ptype_offset > IDPF_CTLQ_MAX_BUF_LEN)
				return -EINVAL;

			/* 0xFFFF indicates end of ptypes */
			if (le16_to_cpu(ptype->ptype_id_10) ==
							IDPF_INVALID_PTYPE_ID)
				return 0;

			if (idpf_is_queue_model_split(vport->rxq_model))
				k = le16_to_cpu(ptype->ptype_id_10);
			else
				k = ptype->ptype_id_8;

			if (ptype->proto_id_count)
				ptype_lkup[k].known = 1;

			for (j = 0; j < ptype->proto_id_count; j++) {
				id = le16_to_cpu(ptype->proto_id[j]);
				switch (id) {
				case VIRTCHNL2_PROTO_HDR_GRE:
					if (pstate.tunnel_state ==
							IDPF_PTYPE_TUNNEL_IP) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_MAC:
					ptype_lkup[k].outer_ip =
						IDPF_RX_PTYPE_OUTER_L2;
					if (pstate.tunnel_state ==
							IDPF_TUN_IP_GRE) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_UDP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_UDP;
					break;
				case VIRTCHNL2_PROTO_HDR_TCP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_TCP;
					break;
				case VIRTCHNL2_PROTO_HDR_SCTP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_SCTP;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_ICMP;
					break;
				case VIRTCHNL2_PROTO_HDR_PAY:
					ptype_lkup[k].payload_layer =
						IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMPV6:
				case VIRTCHNL2_PROTO_HDR_IPV6_EH:
				case VIRTCHNL2_PROTO_HDR_PRE_MAC:
				case VIRTCHNL2_PROTO_HDR_POST_MAC:
				case VIRTCHNL2_PROTO_HDR_ETHERTYPE:
				case VIRTCHNL2_PROTO_HDR_SVLAN:
				case VIRTCHNL2_PROTO_HDR_CVLAN:
				case VIRTCHNL2_PROTO_HDR_MPLS:
				case VIRTCHNL2_PROTO_HDR_MMPLS:
				case VIRTCHNL2_PROTO_HDR_PTP:
				case VIRTCHNL2_PROTO_HDR_CTRL:
				case VIRTCHNL2_PROTO_HDR_LLDP:
				case VIRTCHNL2_PROTO_HDR_ARP:
				case VIRTCHNL2_PROTO_HDR_ECP:
				case VIRTCHNL2_PROTO_HDR_EAPOL:
				case VIRTCHNL2_PROTO_HDR_PPPOD:
				case VIRTCHNL2_PROTO_HDR_PPPOE:
				case VIRTCHNL2_PROTO_HDR_IGMP:
				case VIRTCHNL2_PROTO_HDR_AH:
				case VIRTCHNL2_PROTO_HDR_ESP:
				case VIRTCHNL2_PROTO_HDR_IKE:
				case VIRTCHNL2_PROTO_HDR_NATT_KEEP:
				case VIRTCHNL2_PROTO_HDR_L2TPV2:
				case VIRTCHNL2_PROTO_HDR_L2TPV2_CONTROL:
				case VIRTCHNL2_PROTO_HDR_L2TPV3:
				case VIRTCHNL2_PROTO_HDR_GTP:
				case VIRTCHNL2_PROTO_HDR_GTP_EH:
				case VIRTCHNL2_PROTO_HDR_GTPCV2:
				case VIRTCHNL2_PROTO_HDR_GTPC_TEID:
				case VIRTCHNL2_PROTO_HDR_GTPU:
				case VIRTCHNL2_PROTO_HDR_GTPU_UL:
				case VIRTCHNL2_PROTO_HDR_GTPU_DL:
				case VIRTCHNL2_PROTO_HDR_ECPRI:
				case VIRTCHNL2_PROTO_HDR_VRRP:
				case VIRTCHNL2_PROTO_HDR_OSPF:
				case VIRTCHNL2_PROTO_HDR_TUN:
				case VIRTCHNL2_PROTO_HDR_NVGRE:
				case VIRTCHNL2_PROTO_HDR_VXLAN:
				case VIRTCHNL2_PROTO_HDR_VXLAN_GPE:
				case VIRTCHNL2_PROTO_HDR_GENEVE:
				case VIRTCHNL2_PROTO_HDR_NSH:
				case VIRTCHNL2_PROTO_HDR_QUIC:
				case VIRTCHNL2_PROTO_HDR_PFCP:
				case VIRTCHNL2_PROTO_HDR_PFCP_NODE:
				case VIRTCHNL2_PROTO_HDR_PFCP_SESSION:
				case VIRTCHNL2_PROTO_HDR_RTP:
				case VIRTCHNL2_PROTO_HDR_NO_PROTO:
					break;
				default:
					break;
				}
			}
		}
	}

	return 0;
}

/**
 * idpf_send_ena_dis_loopback_msg - Send virtchnl enable/disable loopback
 *				    message
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_loopback loopback;
	ssize_t reply_sz;

	loopback.vport_id = cpu_to_le32(vport->vport_id);
	loopback.enable = idpf_is_feature_ena(vport, NETIF_F_LOOPBACK);

	xn_params.vc_op = VIRTCHNL2_OP_LOOPBACK;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &loopback;
	xn_params.send_buf.iov_len = sizeof(loopback);
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_add_queues_msg - Send virtchnl add queues message
 * @vport: Virtual port private data structure
 * @num_tx_q: number of transmit queues
 * @num_complq: number of transmit completion queues
 * @num_rx_q: number of receive queues
 * @num_rx_bufq: number of receive buffer queues
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_add_queues_msg(const struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq)
{
	struct virtchnl2_add_queues *vc_msg __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	struct idpf_vport_config *vport_config;
	struct virtchnl2_add_queues aq = {};
	u16 vport_idx = vport->idx;
	ssize_t reply_sz;
	int size;

	vc_msg = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!vc_msg)
		return -ENOMEM;

	vport_config = vport->adapter->vport_config[vport_idx];
	kfree(vport_config->req_qs_chunks);
	vport_config->req_qs_chunks = NULL;

	aq.vport_id = cpu_to_le32(vport->vport_id);
	aq.num_tx_q = cpu_to_le16(num_tx_q);
	aq.num_tx_complq = cpu_to_le16(num_complq);
	aq.num_rx_q = cpu_to_le16(num_rx_q);
	aq.num_rx_bufq = cpu_to_le16(num_rx_bufq);

	xn_params.vc_op = VIRTCHNL2_OP_ADD_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &aq;
	xn_params.send_buf.iov_len = sizeof(aq);
	xn_params.recv_buf.iov_base = vc_msg;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;

	/* compare vc_msg num queues with vport num queues */
	if (le16_to_cpu(vc_msg->num_tx_q) != num_tx_q ||
	    le16_to_cpu(vc_msg->num_rx_q) != num_rx_q ||
	    le16_to_cpu(vc_msg->num_tx_complq) != num_complq ||
	    le16_to_cpu(vc_msg->num_rx_bufq) != num_rx_bufq)
		return -EINVAL;

	size = struct_size(vc_msg, chunks.chunks,
			   le16_to_cpu(vc_msg->chunks.num_chunks));
	if (reply_sz < size)
		return -EIO;

	vport_config->req_qs_chunks = kmemdup(vc_msg, size, GFP_KERNEL);
	if (!vport_config->req_qs_chunks)
		return -ENOMEM;

	return 0;
}

/**
 * idpf_send_create_vport_msg - Send virtchnl create vport message
 * @adapter: Driver specific private structure
 * @max_q: vport max queue info
 *
 * send virtchnl creae vport message
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vc_xn_params xn_params = {};
	u16 idx = adapter->next_vport;
	int err, buf_size;
	ssize_t reply_sz;

	buf_size = sizeof(struct virtchnl2_create_vport);
	if (!adapter->vport_params_reqd[idx]) {
		adapter->vport_params_reqd[idx] = kzalloc(buf_size,
							  GFP_KERNEL);
		if (!adapter->vport_params_reqd[idx])
			return -ENOMEM;
	}

	vport_msg = adapter->vport_params_reqd[idx];
	vport_msg->vport_type = cpu_to_le16(VIRTCHNL2_VPORT_TYPE_DEFAULT);
	vport_msg->vport_index = cpu_to_le16(idx);

	if (adapter->req_tx_splitq)
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	if (adapter->req_rx_splitq)
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	err = idpf_vport_calc_total_qs(adapter, idx, vport_msg, max_q);
	if (err) {
		dev_err(&adapter->pdev->dev, "Enough queues are not available");

		return err;
	}

	if (!adapter->vport_params_recvd[idx]) {
		adapter->vport_params_recvd[idx] = kzalloc(IDPF_CTLQ_MAX_BUF_LEN,
							   GFP_KERNEL);
		if (!adapter->vport_params_recvd[idx]) {
			err = -ENOMEM;
			goto free_vport_params;
		}
	}

	xn_params.vc_op = VIRTCHNL2_OP_CREATE_VPORT;
	xn_params.send_buf.iov_base = vport_msg;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.recv_buf.iov_base = adapter->vport_params_recvd[idx];
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0) {
		err = reply_sz;
		goto free_vport_params;
	}
	if (reply_sz < IDPF_CTLQ_MAX_BUF_LEN) {
		err = -EIO;
		goto free_vport_params;
	}

	return 0;

free_vport_params:
	kfree(adapter->vport_params_recvd[idx]);
	adapter->vport_params_recvd[idx] = NULL;
	kfree(adapter->vport_params_reqd[idx]);
	adapter->vport_params_reqd[idx] = NULL;

	return err;
}

/**
 * idpf_check_supported_desc_ids - Verify we have required descriptor support
 * @vport: virtual port structure
 *
 * Return 0 on success, error on failure
 */
int idpf_check_supported_desc_ids(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	u64 rx_desc_ids, tx_desc_ids;

	vport_msg = adapter->vport_params_recvd[vport->idx];

	rx_desc_ids = le64_to_cpu(vport_msg->rx_desc_ids);
	tx_desc_ids = le64_to_cpu(vport_msg->tx_desc_ids);

	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M)) {
			dev_info(&adapter->pdev->dev, "Minimum RX descriptor support not provided, using the default\n");
			vport_msg->rx_desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
		}
	} else {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M))
			vport->base_rxd = true;
	}

	if (vport->txq_model != VIRTCHNL2_QUEUE_MODEL_SPLIT)
		return 0;

	if ((tx_desc_ids & MIN_SUPPORT_TXDID) != MIN_SUPPORT_TXDID) {
		dev_info(&adapter->pdev->dev, "Minimum TX descriptor support not provided, using the default\n");
		vport_msg->tx_desc_ids = cpu_to_le64(MIN_SUPPORT_TXDID);
	}

	return 0;
}

/**
 * idpf_send_destroy_vport_msg - Send virtchnl destroy vport message
 * @vport: virtual port data structure
 *
 * Send virtchnl destroy vport message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_destroy_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_DESTROY_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_enable_vport_msg - Send virtchnl enable vport message
 * @vport: virtual port data structure
 *
 * Send enable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_ENABLE_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_disable_vport_msg - Send virtchnl disable vport message
 * @vport: virtual port data structure
 *
 * Send disable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_disable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_vport v_id;
	ssize_t reply_sz;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	xn_params.vc_op = VIRTCHNL2_OP_DISABLE_VPORT;
	xn_params.send_buf.iov_base = &v_id;
	xn_params.send_buf.iov_len = sizeof(v_id);
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_config_tx_queues_msg - Send virtchnl config tx queues message
 * @vport: virtual port data structure
 *
 * Send config tx queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_tx_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_config_tx_queues *ctq __free(kfree) = NULL;
	struct virtchnl2_txq_info *qi __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	u32 config_sz, chunk_sz, buf_sz;
	int totqs, num_msgs, num_chunks;
	ssize_t reply_sz;
	int i, k = 0;

	totqs = vport->num_txq + vport->num_complq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_txq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j, sched_mode;

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			qi[k].queue_id =
				cpu_to_le32(tx_qgrp->txqs[j]->q_id);
			qi[k].model =
				cpu_to_le16(vport->txq_model);
			qi[k].type =
				cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			qi[k].ring_len =
				cpu_to_le16(tx_qgrp->txqs[j]->desc_count);
			qi[k].dma_ring_addr =
				cpu_to_le64(tx_qgrp->txqs[j]->dma);
			if (idpf_is_queue_model_split(vport->txq_model)) {
				struct idpf_queue *q = tx_qgrp->txqs[j];

				qi[k].tx_compl_queue_id =
					cpu_to_le16(tx_qgrp->complq->q_id);
				qi[k].relative_queue_id = cpu_to_le16(j);

				if (test_bit(__IDPF_Q_FLOW_SCH_EN, q->flags))
					qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_FLOW);
				else
					qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);
			} else {
				qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);
			}
		}

		if (!idpf_is_queue_model_split(vport->txq_model))
			continue;

		qi[k].queue_id = cpu_to_le32(tx_qgrp->complq->q_id);
		qi[k].model = cpu_to_le16(vport->txq_model);
		qi[k].type = cpu_to_le32(tx_qgrp->complq->q_type);
		qi[k].ring_len = cpu_to_le16(tx_qgrp->complq->desc_count);
		qi[k].dma_ring_addr = cpu_to_le64(tx_qgrp->complq->dma);

		if (test_bit(__IDPF_Q_FLOW_SCH_EN, tx_qgrp->complq->flags))
			sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
		else
			sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_QUEUE;
		qi[k].sched_mode = cpu_to_le16(sched_mode);

		k++;
	}

	/* Make sure accounting agrees */
	if (k != totqs)
		return -EINVAL;

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_sz = sizeof(struct virtchnl2_config_tx_queues);
	chunk_sz = sizeof(struct virtchnl2_txq_info);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   totqs);
	num_msgs = DIV_ROUND_UP(totqs, num_chunks);

	buf_sz = struct_size(ctq, qinfo, num_chunks);
	ctq = kzalloc(buf_sz, GFP_KERNEL);
	if (!ctq)
		return -ENOMEM;

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	for (i = 0, k = 0; i < num_msgs; i++) {
		memset(ctq, 0, buf_sz);
		ctq->vport_id = cpu_to_le32(vport->vport_id);
		ctq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(ctq->qinfo, &qi[k], chunk_sz * num_chunks);

		xn_params.send_buf.iov_base = ctq;
		xn_params.send_buf.iov_len = buf_sz;
		reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		k += num_chunks;
		totqs -= num_chunks;
		num_chunks = min(num_chunks, totqs);
		/* Recalculate buffer size */
		buf_sz = struct_size(ctq, qinfo, num_chunks);
	}

	return 0;
}

/**
 * idpf_send_config_rx_queues_msg - Send virtchnl config rx queues message
 * @vport: virtual port data structure
 *
 * Send config rx queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_rx_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_config_rx_queues *crq __free(kfree) = NULL;
	struct virtchnl2_rxq_info *qi __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	u32 config_sz, chunk_sz, buf_sz;
	int totqs, num_msgs, num_chunks;
	ssize_t reply_sz;
	int i, k = 0;

	totqs = vport->num_rxq + vport->num_bufq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_rxq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		u16 num_rxq;
		int j;

		if (!idpf_is_queue_model_split(vport->rxq_model))
			goto setup_rxqs;

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++) {
			struct idpf_queue *bufq =
				&rx_qgrp->splitq.bufq_sets[j].bufq;

			qi[k].queue_id = cpu_to_le32(bufq->q_id);
			qi[k].model = cpu_to_le16(vport->rxq_model);
			qi[k].type = cpu_to_le32(bufq->q_type);
			qi[k].desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
			qi[k].ring_len = cpu_to_le16(bufq->desc_count);
			qi[k].dma_ring_addr = cpu_to_le64(bufq->dma);
			qi[k].data_buffer_size = cpu_to_le32(bufq->rx_buf_size);
			qi[k].buffer_notif_stride = bufq->rx_buf_stride;
			qi[k].rx_buffer_low_watermark =
				cpu_to_le16(bufq->rx_buffer_low_watermark);
			if (idpf_is_feature_ena(vport, NETIF_F_GRO_HW))
				qi[k].qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);
		}

setup_rxqs:
		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			struct idpf_queue *rxq;

			if (!idpf_is_queue_model_split(vport->rxq_model)) {
				rxq = rx_qgrp->singleq.rxqs[j];
				goto common_qi_fields;
			}
			rxq = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			qi[k].rx_bufq1_id =
			  cpu_to_le16(rxq->rxq_grp->splitq.bufq_sets[0].bufq.q_id);
			if (vport->num_bufqs_per_qgrp > IDPF_SINGLE_BUFQ_PER_RXQ_GRP) {
				qi[k].bufq2_ena = IDPF_BUFQ2_ENA;
				qi[k].rx_bufq2_id =
				  cpu_to_le16(rxq->rxq_grp->splitq.bufq_sets[1].bufq.q_id);
			}
			qi[k].rx_buffer_low_watermark =
				cpu_to_le16(rxq->rx_buffer_low_watermark);
			if (idpf_is_feature_ena(vport, NETIF_F_GRO_HW))
				qi[k].qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);

common_qi_fields:
			if (rxq->rx_hsplit_en) {
				qi[k].qflags |=
					cpu_to_le16(VIRTCHNL2_RXQ_HDR_SPLIT);
				qi[k].hdr_buffer_size =
					cpu_to_le16(rxq->rx_hbuf_size);
			}
			qi[k].queue_id = cpu_to_le32(rxq->q_id);
			qi[k].model = cpu_to_le16(vport->rxq_model);
			qi[k].type = cpu_to_le32(rxq->q_type);
			qi[k].ring_len = cpu_to_le16(rxq->desc_count);
			qi[k].dma_ring_addr = cpu_to_le64(rxq->dma);
			qi[k].max_pkt_size = cpu_to_le32(rxq->rx_max_pkt_size);
			qi[k].data_buffer_size = cpu_to_le32(rxq->rx_buf_size);
			qi[k].qflags |=
				cpu_to_le16(VIRTCHNL2_RX_DESC_SIZE_32BYTE);
			qi[k].desc_ids = cpu_to_le64(rxq->rxdids);
		}
	}

	/* Make sure accounting agrees */
	if (k != totqs)
		return -EINVAL;

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_sz = sizeof(struct virtchnl2_config_rx_queues);
	chunk_sz = sizeof(struct virtchnl2_rxq_info);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   totqs);
	num_msgs = DIV_ROUND_UP(totqs, num_chunks);

	buf_sz = struct_size(crq, qinfo, num_chunks);
	crq = kzalloc(buf_sz, GFP_KERNEL);
	if (!crq)
		return -ENOMEM;

	xn_params.vc_op = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	for (i = 0, k = 0; i < num_msgs; i++) {
		memset(crq, 0, buf_sz);
		crq->vport_id = cpu_to_le32(vport->vport_id);
		crq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(crq->qinfo, &qi[k], chunk_sz * num_chunks);

		xn_params.send_buf.iov_base = crq;
		xn_params.send_buf.iov_len = buf_sz;
		reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		k += num_chunks;
		totqs -= num_chunks;
		num_chunks = min(num_chunks, totqs);
		/* Recalculate buffer size */
		buf_sz = struct_size(crq, qinfo, num_chunks);
	}

	return 0;
}

/**
 * idpf_send_config_queues_msg - Send config queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send config queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_queues_msg(struct idpf_vport *vport)
{
	int err;

	err = idpf_send_config_tx_queues_msg(vport);
	if (err)
		return err;

	return idpf_send_config_rx_queues_msg(vport);
}

/**
 * idpf_convert_reg_to_queue_chunks - Copy queue chunk information to the right
 * structure
 * @dchunks: Destination chunks to store data to
 * @schunks: Source chunks to copy data from
 * @num_chunks: number of chunks to copy
 */
static
void idpf_convert_reg_to_queue_chunks(struct virtchnl2_queue_chunk *dchunks,
				      struct virtchnl2_queue_reg_chunk *schunks,
				      u16 num_chunks)
{
	u16 i;

	for (i = 0; i < num_chunks; i++) {
		dchunks[i].type = schunks[i].type;
		dchunks[i].start_queue_id = schunks[i].start_queue_id;
		dchunks[i].num_queues = schunks[i].num_queues;
	}
}

/**
 * idpf_send_delete_queues_msg - send delete queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send delete queues virtchnl message. Return 0 on success, negative on
 * failure.
 */
int idpf_send_delete_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_del_ena_dis_queues *eq __free(kfree) = NULL;
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vc_xn_params xn_params = {};
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	ssize_t reply_sz;
	u16 num_chunks;
	int buf_size;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		chunks = &vport_config->req_qs_chunks->chunks;
	} else {
		vport_params = vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	num_chunks = le16_to_cpu(chunks->num_chunks);
	buf_size = struct_size(eq, chunks.chunks, num_chunks);

	eq = kzalloc(buf_size, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	idpf_convert_reg_to_queue_chunks(eq->chunks.chunks, chunks->chunks,
					 num_chunks);

	xn_params.vc_op = VIRTCHNL2_OP_DEL_QUEUES;
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = eq;
	xn_params.send_buf.iov_len = buf_size;
	reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_send_ena_dis_queues_msg - Send virtchnl enable or disable
 * queues message
 * @vport: virtual port data structure
 * @ena: if true enable, false disable
 *
 * Send enable or disable queues virtchnl message. Returns 0 on success,
 * negative on failure.
 */
static int idpf_send_ena_dis_queues_msg(struct idpf_vport *vport, bool ena)
{
	struct virtchnl2_del_ena_dis_queues *eq __free(kfree) = NULL;
	struct virtchnl2_queue_chunk *qc __free(kfree) = NULL;
	u32 num_msgs, num_chunks, num_txq, num_rxq, num_q;
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_queue_chunks *qcs;
	u32 config_sz, chunk_sz, buf_sz;
	ssize_t reply_sz;
	int i, j, k = 0;

	num_txq = vport->num_txq + vport->num_complq;
	num_rxq = vport->num_rxq + vport->num_bufq;
	num_q = num_txq + num_rxq;
	buf_sz = sizeof(struct virtchnl2_queue_chunk) * num_q;
	qc = kzalloc(buf_sz, GFP_KERNEL);
	if (!qc)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			qc[k].type = cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			qc[k].start_queue_id = cpu_to_le32(tx_qgrp->txqs[j]->q_id);
			qc[k].num_queues = cpu_to_le32(IDPF_NUMQ_PER_CHUNK);
		}
	}
	if (vport->num_txq != k)
		return -EINVAL;

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto setup_rx;

	for (i = 0; i < vport->num_txq_grp; i++, k++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		qc[k].type = cpu_to_le32(tx_qgrp->complq->q_type);
		qc[k].start_queue_id = cpu_to_le32(tx_qgrp->complq->q_id);
		qc[k].num_queues = cpu_to_le32(IDPF_NUMQ_PER_CHUNK);
	}
	if (vport->num_complq != (k - vport->num_txq))
		return -EINVAL;

setup_rx:
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			if (idpf_is_queue_model_split(vport->rxq_model)) {
				qc[k].start_queue_id =
				cpu_to_le32(rx_qgrp->splitq.rxq_sets[j]->rxq.q_id);
				qc[k].type =
				cpu_to_le32(rx_qgrp->splitq.rxq_sets[j]->rxq.q_type);
			} else {
				qc[k].start_queue_id =
				cpu_to_le32(rx_qgrp->singleq.rxqs[j]->q_id);
				qc[k].type =
				cpu_to_le32(rx_qgrp->singleq.rxqs[j]->q_type);
			}
			qc[k].num_queues = cpu_to_le32(IDPF_NUMQ_PER_CHUNK);
		}
	}
	if (vport->num_rxq != k - (vport->num_txq + vport->num_complq))
		return -EINVAL;

	if (!idpf_is_queue_model_split(vport->rxq_model))
		goto send_msg;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++) {
			struct idpf_queue *q;

			q = &rx_qgrp->splitq.bufq_sets[j].bufq;
			qc[k].type = cpu_to_le32(q->q_type);
			qc[k].start_queue_id = cpu_to_le32(q->q_id);
			qc[k].num_queues = cpu_to_le32(IDPF_NUMQ_PER_CHUNK);
		}
	}
	if (vport->num_bufq != k - (vport->num_txq +
				    vport->num_complq +
				    vport->num_rxq))
		return -EINVAL;

send_msg:
	/* Chunk up the queue info into multiple messages */
	config_sz = sizeof(struct virtchnl2_del_ena_dis_queues);
	chunk_sz = sizeof(struct virtchnl2_queue_chunk);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   num_q);
	num_msgs = DIV_ROUND_UP(num_q, num_chunks);

	buf_sz = struct_size(eq, chunks.chunks, num_chunks);
	eq = kzalloc(buf_sz, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	if (ena) {
		xn_params.vc_op = VIRTCHNL2_OP_ENABLE_QUEUES;
		xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	} else {
		xn_params.vc_op = VIRTCHNL2_OP_DISABLE_QUEUES;
		xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	}

	for (i = 0, k = 0; i < num_msgs; i++) {
		memset(eq, 0, buf_sz);
		eq->vport_id = cpu_to_le32(vport->vport_id);
		eq->chunks.num_chunks = cpu_to_le16(num_chunks);
		qcs = &eq->chunks;
		memcpy(qcs->chunks, &qc[k], chunk_sz * num_chunks);

		xn_params.send_buf.iov_base = eq;
		xn_params.send_buf.iov_len = buf_sz;
		reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		k += num_chunks;
		num_q -= num_chunks;
		num_chunks = min(num_chunks, num_q);
		/* Recalculate buffer size */
		buf_sz = struct_size(eq, chunks.chunks, num_chunks);
	}

	return 0;
}

/**
 * idpf_send_map_unmap_queue_vector_msg - Send virtchnl map or unmap queue
 * vector message
 * @vport: virtual port data structure
 * @map: true for map and false for unmap
 *
 * Send map or unmap queue vector virtchnl message.  Returns 0 on success,
 * negative on failure.
 */
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport, bool map)
{
	struct virtchnl2_queue_vector_maps *vqvm __free(kfree) = NULL;
	struct virtchnl2_queue_vector *vqv __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	u32 config_sz, chunk_sz, buf_sz;
	u32 num_msgs, num_chunks, num_q;
	ssize_t reply_sz;
	int i, j, k = 0;

	num_q = vport->num_txq + vport->num_rxq;

	buf_sz = sizeof(struct virtchnl2_queue_vector) * num_q;
	vqv = kzalloc(buf_sz, GFP_KERNEL);
	if (!vqv)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			vqv[k].queue_type = cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			vqv[k].queue_id = cpu_to_le32(tx_qgrp->txqs[j]->q_id);

			if (idpf_is_queue_model_split(vport->txq_model)) {
				vqv[k].vector_id =
				cpu_to_le16(tx_qgrp->complq->q_vector->v_idx);
				vqv[k].itr_idx =
				cpu_to_le32(tx_qgrp->complq->q_vector->tx_itr_idx);
			} else {
				vqv[k].vector_id =
				cpu_to_le16(tx_qgrp->txqs[j]->q_vector->v_idx);
				vqv[k].itr_idx =
				cpu_to_le32(tx_qgrp->txqs[j]->q_vector->tx_itr_idx);
			}
		}
	}

	if (vport->num_txq != k)
		return -EINVAL;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		u16 num_rxq;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			struct idpf_queue *rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				rxq = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				rxq = rx_qgrp->singleq.rxqs[j];

			vqv[k].queue_type = cpu_to_le32(rxq->q_type);
			vqv[k].queue_id = cpu_to_le32(rxq->q_id);
			vqv[k].vector_id = cpu_to_le16(rxq->q_vector->v_idx);
			vqv[k].itr_idx = cpu_to_le32(rxq->q_vector->rx_itr_idx);
		}
	}

	if (idpf_is_queue_model_split(vport->txq_model)) {
		if (vport->num_rxq != k - vport->num_complq)
			return -EINVAL;
	} else {
		if (vport->num_rxq != k - vport->num_txq)
			return -EINVAL;
	}

	/* Chunk up the vector info into multiple messages */
	config_sz = sizeof(struct virtchnl2_queue_vector_maps);
	chunk_sz = sizeof(struct virtchnl2_queue_vector);

	num_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(config_sz, chunk_sz),
			   num_q);
	num_msgs = DIV_ROUND_UP(num_q, num_chunks);

	buf_sz = struct_size(vqvm, qv_maps, num_chunks);
	vqvm = kzalloc(buf_sz, GFP_KERNEL);
	if (!vqvm)
		return -ENOMEM;

	if (map) {
		xn_params.vc_op = VIRTCHNL2_OP_MAP_QUEUE_VECTOR;
		xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	} else {
		xn_params.vc_op = VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR;
		xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	}

	for (i = 0, k = 0; i < num_msgs; i++) {
		memset(vqvm, 0, buf_sz);
		xn_params.send_buf.iov_base = vqvm;
		xn_params.send_buf.iov_len = buf_sz;
		vqvm->vport_id = cpu_to_le32(vport->vport_id);
		vqvm->num_qv_maps = cpu_to_le16(num_chunks);
		memcpy(vqvm->qv_maps, &vqv[k], chunk_sz * num_chunks);

		reply_sz = idpf_vc_xn_exec(vport->adapter, &xn_params);
		if (reply_sz < 0)
			return reply_sz;

		k += num_chunks;
		num_q -= num_chunks;
		num_chunks = min(num_chunks, num_q);
		/* Recalculate buffer size */
		buf_sz = struct_size(vqvm, qv_maps, num_chunks);
	}

	return 0;
}

/**
 * idpf_send_enable_queues_msg - send enable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send enable queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_queues_msg(struct idpf_vport *vport)
{
	return idpf_send_ena_dis_queues_msg(vport, true);
}

/**
 * idpf_send_disable_queues_msg - send disable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send disable queues virtchnl message.  Returns 0 on success, negative
 * on failure.
 */
int idpf_send_disable_queues_msg(struct idpf_vport *vport)
{
	int err, i;

	err = idpf_send_ena_dis_queues_msg(vport, false);
	if (err)
		return err;

	/* switch to poll mode as interrupts will be disabled after disable
	 * queues virtchnl message is sent
	 */
	for (i = 0; i < vport->num_txq; i++)
		set_bit(__IDPF_Q_POLL_MODE, vport->txqs[i]->flags);

	/* schedule the napi to receive all the marker packets */
	local_bh_disable();
	for (i = 0; i < vport->num_q_vectors; i++)
		napi_schedule(&vport->q_vectors[i].napi);
	local_bh_enable();

	return idpf_wait_for_marker_event(vport);
}

/**
 * __idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 * @qids: queue ids
 * @num_qids: number of queue ids
 * @q_type: type of queue
 *
 * Will initialize all queue ids with ids received as mailbox
 * parameters. Returns number of queue ids initialized.
 */
static int __idpf_vport_queue_ids_init(struct idpf_vport *vport,
				       const u32 *qids,
				       int num_qids,
				       u32 q_type)
{
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq && k < num_qids; j++, k++) {
				tx_qgrp->txqs[j]->q_id = qids[k];
				tx_qgrp->txqs[j]->q_type =
					VIRTCHNL2_QUEUE_TYPE_TX;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u16 num_rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				num_rxq = rx_qgrp->splitq.num_rxq_sets;
			else
				num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq && k < num_qids; j++, k++) {
				if (idpf_is_queue_model_split(vport->rxq_model))
					q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
				else
					q = rx_qgrp->singleq.rxqs[j];
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		for (i = 0; i < vport->num_txq_grp && k < num_qids; i++, k++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			tx_qgrp->complq->q_id = qids[k];
			tx_qgrp->complq->q_type =
				VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u8 num_bufqs = vport->num_bufqs_per_qgrp;

			for (j = 0; j < num_bufqs && k < num_qids; j++, k++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_vport_get_queue_ids - Initialize queue id from Mailbox parameters
 * @qids: Array of queue ids
 * @num_qids: number of queue ids
 * @q_type: queue model
 * @chunks: queue ids received over mailbox
 *
 * Will initialize all queue ids with ids received as mailbox parameters
 * Returns number of ids filled
 */
static int idpf_vport_get_queue_ids(u32 *qids, int num_qids, u16 q_type,
				    struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	u32 num_q_id_filled = 0, i;
	u32 start_q_id, num_q;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		start_q_id = le32_to_cpu(chunk->start_queue_id);

		for (i = 0; i < num_q; i++) {
			if ((num_q_id_filled + i) < num_qids) {
				qids[num_q_id_filled + i] = start_q_id;
				start_q_id++;
			} else {
				break;
			}
		}
		num_q_id_filled = num_q_id_filled + i;
	}

	return num_q_id_filled;
}

/**
 * idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 *
 * Will initialize all queue ids with ids received as mailbox parameters.
 * Returns 0 on success, negative if all the queues are not initialized.
 */
int idpf_vport_queue_ids_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int num_ids, err = 0;
	u16 q_type;
	u32 *qids;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
			(struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	qids = kcalloc(IDPF_MAX_QIDS, sizeof(u32), GFP_KERNEL);
	if (!qids)
		return -ENOMEM;

	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_TX,
					   chunks);
	if (num_ids < vport->num_txq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_ids < vport->num_txq) {
		err = -EINVAL;
		goto mem_rel;
	}

	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_RX,
					   chunks);
	if (num_ids < vport->num_rxq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_RX);
	if (num_ids < vport->num_rxq) {
		err = -EINVAL;
		goto mem_rel;
	}

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto check_rxq;

	q_type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < vport->num_complq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids, q_type);
	if (num_ids < vport->num_complq) {
		err = -EINVAL;
		goto mem_rel;
	}

check_rxq:
	if (!idpf_is_queue_model_split(vport->rxq_model))
		goto mem_rel;

	q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < vport->num_bufq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids, q_type);
	if (num_ids < vport->num_bufq)
		err = -EINVAL;

mem_rel:
	kfree(qids);

	return err;
}

/**
 * idpf_vport_adjust_qs - Adjust to new requested queues
 * @vport: virtual port data struct
 *
 * Renegotiate queues.  Returns 0 on success, negative on failure.
 */
int idpf_vport_adjust_qs(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport vport_msg;
	int err;

	vport_msg.txq_model = cpu_to_le16(vport->txq_model);
	vport_msg.rxq_model = cpu_to_le16(vport->rxq_model);
	err = idpf_vport_calc_total_qs(vport->adapter, vport->idx, &vport_msg,
				       NULL);
	if (err)
		return err;

	idpf_vport_init_num_qs(vport, &vport_msg);
	idpf_vport_calc_num_q_groups(vport);

	return 0;
}
