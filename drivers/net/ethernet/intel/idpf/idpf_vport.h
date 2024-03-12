/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_VPORT_H_
#define _IDPF_VPORT_H_

struct idpf_vport_max_q;

#include "idpf_txrx.h"

#define IDPF_DIM_PROFILE_SLOTS  5

#define IDPF_CAP_RSS (\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV4_OTHER	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV6_OTHER)

#define IDPF_CAP_RSC (\
	VIRTCHNL2_CAP_RSC_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV6_TCP)

#define IDPF_CAP_HSPLIT	(\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6)

#define IDPF_CAP_RX_CSUM_L4V4 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP)

#define IDPF_CAP_RX_CSUM_L4V6 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IDPF_CAP_RX_CSUM (\
	VIRTCHNL2_CAP_RX_CSUM_L3_IPV4		|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IDPF_CAP_SCTP_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

#define IDPF_CAP_TUNNEL_TX_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL)

/**
 * enum idpf_vport_state - Current vport state
 * @__IDPF_VPORT_DOWN: Vport is down
 * @__IDPF_VPORT_UP: Vport is up
 * @__IDPF_VPORT_STATE_LAST: Must be last, number of states
 */
enum idpf_vport_state {
	__IDPF_VPORT_DOWN,
	__IDPF_VPORT_UP,
	__IDPF_VPORT_STATE_LAST,
};

/**
 * struct idpf_vport_max_q - Queue limits
 * @max_rxq: Maximum number of RX queues supported
 * @max_txq: Maixmum number of TX queues supported
 * @max_bufq: In splitq, maximum number of buffer queues supported
 * @max_complq: In splitq, maximum number of completion queues supported
 */
struct idpf_vport_max_q {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/**
 * enum idpf_vport_flags - Vport flags
 * @IDPF_VPORT_DEL_QUEUES: To send delete queues message
 * @IDPF_VPORT_SW_MARKER: Indicate TX pipe drain software marker packets
 *			  processing is done
 * @IDPF_VPORT_FLAGS_NBITS: Must be last
 */
enum idpf_vport_flags {
	IDPF_VPORT_DEL_QUEUES,
	IDPF_VPORT_SW_MARKER,
	IDPF_VPORT_FLAGS_NBITS,
};

struct idpf_port_stats {
	struct u64_stats_sync stats_sync;
	u64_stats_t rx_hw_csum_err;
	u64_stats_t rx_hsplit;
	u64_stats_t rx_hsplit_hbo;
	u64_stats_t rx_bad_descs;
	u64_stats_t tx_linearize;
	u64_stats_t tx_busy;
	u64_stats_t tx_drops;
	u64_stats_t tx_dma_map_errs;
	struct virtchnl2_vport_stats vport_stats;
};

/**
 * enum idpf_user_flags
 * @__IDPF_USER_FLAG_HSPLIT: header split state
 * @__IDPF_PROMISC_UC: Unicast promiscuous mode
 * @__IDPF_PROMISC_MC: Multicast promiscuous mode
 * @__IDPF_USER_FLAGS_NBITS: Must be last
 */
enum idpf_user_flags {
	__IDPF_USER_FLAG_HSPLIT = 0U,
	__IDPF_PROMISC_UC = 32,
	__IDPF_PROMISC_MC,

	__IDPF_USER_FLAGS_NBITS,
};

/**
 * struct idpf_rss_data - Associated RSS data
 * @rss_key_size: Size of RSS hash key
 * @rss_key: RSS hash key
 * @rss_lut_size: Size of RSS lookup table
 * @rss_lut: RSS lookup table
 * @cached_lut: Used to restore previously init RSS lut
 */
struct idpf_rss_data {
	u16 rss_key_size;
	u8 *rss_key;
	u16 rss_lut_size;
	u32 *rss_lut;
	u32 *cached_lut;
};

/**
 * struct idpf_vport_user_config_data - User defined configuration values for
 *					each vport.
 * @rss_data: See struct idpf_rss_data
 * @num_req_tx_qs: Number of user requested TX queues through ethtool
 * @num_req_rx_qs: Number of user requested RX queues through ethtool
 * @num_req_txq_desc: Number of user requested TX queue descriptors through
 *		      ethtool
 * @num_req_rxq_desc: Number of user requested RX queue descriptors through
 *		      ethtool
 * @user_flags: User toggled config flags
 * @mac_filter_list: List of MAC filters
 *
 * Used to restore configuration after a reset as the vport will get wiped.
 */
struct idpf_vport_user_config_data {
	struct idpf_rss_data rss_data;
	u16 num_req_tx_qs;
	u16 num_req_rx_qs;
	u32 num_req_txq_desc;
	u32 num_req_rxq_desc;
	DECLARE_BITMAP(user_flags, __IDPF_USER_FLAGS_NBITS);
	struct list_head mac_filter_list;
};

/**
 * enum idpf_vport_config_flags - Vport config flags
 * @IDPF_VPORT_REG_NETDEV: Register netdev
 * @IDPF_VPORT_UP_REQUESTED: Set if interface up is requested on core reset
 * @IDPF_VPORT_CONFIG_FLAGS_NBITS: Must be last
 */
enum idpf_vport_config_flags {
	IDPF_VPORT_REG_NETDEV,
	IDPF_VPORT_UP_REQUESTED,
	IDPF_VPORT_CONFIG_FLAGS_NBITS,
};

/**
 * struct idpf_avail_queue_info
 * @avail_rxq: Available RX queues
 * @avail_txq: Available TX queues
 * @avail_bufq: Available buffer queues
 * @avail_complq: Available completion queues
 *
 * Maintain total queues available after allocating max queues to each vport.
 */
struct idpf_avail_queue_info {
	u16 avail_rxq;
	u16 avail_txq;
	u16 avail_bufq;
	u16 avail_complq;
};

/**
 * struct idpf_vport_config - Vport configuration data
 * @user_config: see struct idpf_vport_user_config_data
 * @max_q: Maximum possible queues
 * @req_qs_chunks: Queue chunk data for requested queues
 * @mac_filter_list_lock: Lock to protect mac filters
 * @flags: See enum idpf_vport_config_flags
 */
struct idpf_vport_config {
	struct idpf_vport_user_config_data user_config;
	struct idpf_vport_max_q max_q;
	struct virtchnl2_add_queues *req_qs_chunks;
	spinlock_t mac_filter_list_lock;
	DECLARE_BITMAP(flags, IDPF_VPORT_CONFIG_FLAGS_NBITS);
};

/**
 * struct idpf_vport - Handle for netdevices and queue resources
 * @num_txq: Number of allocated TX queues
 * @num_complq: Number of allocated completion queues
 * @txq_desc_count: TX queue descriptor count
 * @complq_desc_count: Completion queue descriptor count
 * @compln_clean_budget: Work budget for completion clean
 * @num_txq_grp: Number of TX queue groups
 * @txq_grps: Array of TX queue groups
 * @txq_model: Split queue or single queue queuing model
 * @txqs: Used only in hotpath to get to the right queue very fast
 * @crc_enable: Enable CRC insertion offload
 * @num_rxq: Number of allocated RX queues
 * @num_bufq: Number of allocated buffer queues
 * @rxq_desc_count: RX queue descriptor count. *MUST* have enough descriptors
 *		    to complete all buffer descriptors for all buffer queues in
 *		    the worst case.
 * @num_bufqs_per_qgrp: Buffer queues per RX queue in a given grouping
 * @bufq_desc_count: Buffer queue descriptor count
 * @bufq_size: Size of buffers in ring (e.g. 2K, 4K, etc)
 * @num_rxq_grp: Number of RX queues in a group
 * @rxq_grps: Total number of RX groups. Number of groups * number of RX per
 *	      group will yield total number of RX queues.
 * @rxq_model: Splitq queue or single queue queuing model
 * @rx_ptype_lkup: Lookup table for ptypes on RX
 * @adapter: back pointer to associated adapter
 * @netdev: Associated net_device. Each vport should have one and only one
 *	    associated netdev.
 * @flags: See enum idpf_vport_flags
 * @vport_type: Default SRIOV, SIOV, etc.
 * @vport_id: Device given vport identifier
 * @idx: Software index in adapter vports struct
 * @default_vport: Use this vport if one isn't specified
 * @base_rxd: True if the driver should use base descriptors instead of flex
 * @num_q_vectors: Number of IRQ vectors allocated
 * @q_vectors: Array of queue vectors
 * @q_vector_idxs: Starting index of queue vectors
 * @max_mtu: device given max possible MTU
 * @default_mac_addr: device will give a default MAC to use
 * @rx_itr_profile: RX profiles for Dynamic Interrupt Moderation
 * @tx_itr_profile: TX profiles for Dynamic Interrupt Moderation
 * @port_stats: per port csum, header split, and other offload stats
 * @link_up: True if link is up
 * @link_speed_mbps: Link speed in mbps
 * @sw_marker_wq: workqueue for marker packets
 */
struct idpf_vport {
	u16 num_txq;
	u16 num_complq;
	u32 txq_desc_count;
	u32 complq_desc_count;
	u32 compln_clean_budget;
	u16 num_txq_grp;
	struct idpf_txq_group *txq_grps;
	u32 txq_model;
	struct idpf_queue **txqs;
	bool crc_enable;

	u16 num_rxq;
	u16 num_bufq;
	u32 rxq_desc_count;
	u8 num_bufqs_per_qgrp;
	u32 bufq_desc_count[IDPF_MAX_BUFQS_PER_RXQ_GRP];
	u32 bufq_size[IDPF_MAX_BUFQS_PER_RXQ_GRP];
	u16 num_rxq_grp;
	struct idpf_rxq_group *rxq_grps;
	u32 rxq_model;
	struct idpf_rx_ptype_decoded rx_ptype_lkup[IDPF_RX_MAX_PTYPE];

	struct idpf_adapter *adapter;
	struct net_device *netdev;
	DECLARE_BITMAP(flags, IDPF_VPORT_FLAGS_NBITS);
	u16 vport_type;
	u32 vport_id;
	u16 idx;
	bool default_vport;
	bool base_rxd;

	u16 num_q_vectors;
	struct idpf_q_vector *q_vectors;
	u16 *q_vector_idxs;
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];
	u16 rx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	u16 tx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	struct idpf_port_stats port_stats;

	bool link_up;
	u32 link_speed_mbps;

	wait_queue_head_t sw_marker_wq;
};

/**
 * idpf_is_queue_model_split - check if queue model is split
 * @q_model: queue model single or split
 *
 * Returns true if queue model is split else false
 */
static inline int idpf_is_queue_model_split(u16 q_model)
{
	return q_model == VIRTCHNL2_QUEUE_MODEL_SPLIT;
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

void idpf_vport_stop(struct idpf_vport *vport);
int idpf_vport_open(struct idpf_vport *vport, bool alloc_res);
void idpf_vport_rel(struct idpf_vport *vport);
void idpf_vport_dealloc(struct idpf_vport *vport);
u8 idpf_vport_get_hsplit(const struct idpf_vport *vport);
bool idpf_vport_set_hsplit(const struct idpf_vport *vport, u8 val);
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport, bool get);
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport, bool get);
struct idpf_vport *idpf_vport_alloc(struct idpf_adapter *adapter,
				    struct idpf_vport_max_q *max_q);
void idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q);
void idpf_set_vport_state(struct idpf_adapter *adapter);
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_reset_cause reset_cause);
void idpf_handle_event_link(struct idpf_adapter *adapter,
			    const struct virtchnl2_event *v2e);
struct idpf_vport *idpf_vid_to_vport(struct idpf_adapter *adapter, u32 v_id);
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q);
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_vport_adjust_qs(struct idpf_vport *vport);

int idpf_send_delete_queues_msg(struct idpf_vport *vport);
int idpf_send_enable_queues_msg(struct idpf_vport *vport);
int idpf_send_disable_queues_msg(struct idpf_vport *vport);
int idpf_send_config_queues_msg(struct idpf_vport *vport);

u32 idpf_get_vport_id(struct idpf_vport *vport);
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_send_destroy_vport_msg(struct idpf_vport *vport);
int idpf_send_enable_vport_msg(struct idpf_vport *vport);
int idpf_send_disable_vport_msg(struct idpf_vport *vport);

int idpf_check_supported_desc_ids(struct idpf_vport *vport);
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport);
int idpf_send_get_stats_msg(struct idpf_vport *vport);
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport, bool map);
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport);
int idpf_send_add_queues_msg(const struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq);
int idpf_queue_reg_init(struct idpf_vport *vport);
int idpf_vport_queue_ids_init(struct idpf_vport *vport);
int idpf_vport_manage_rss_lut(struct idpf_vport *vport);
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport);

#endif /* !_IDPF_VPORT_H_ */
