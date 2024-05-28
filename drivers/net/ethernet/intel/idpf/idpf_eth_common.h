/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_ETH_COMMON_H_
#define _IDPF_ETH_COMMON_H_

#define IDPF_LARGE_MAX_Q			256
/* Mailbox Queue */
#define IDPF_MAX_MBXQ				1

#define GETMAXVAL(num_bits)		GENMASK((num_bits) - 1, 0)
#define IDPF_MAX_BUFQS_PER_RXQ_GRP		2

#define IDPF_NO_FREE_SLOT		0xffff
#define IDPF_NUM_CHUNKS_PER_MSG(struct_sz, chunk_sz)	\
	((IDPF_CTLQ_MAX_BUF_LEN - (struct_sz)) / (chunk_sz))

#define IDPF_MAX_Q				16
#define IDPF_MIN_Q				2

#define IDPF_VC_XN_MIN_TIMEOUT_MSEC	2000
#define IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC	(60 * 1000)
#define IDPF_VC_XN_IDX_M		GENMASK(7, 0)
#define IDPF_VC_XN_SALT_M		GENMASK(15, 8)
#define IDPF_VC_XN_RING_LEN		U8_MAX

/**
 * enum idpf_vc_xn_state - Virtchnl transaction status
 * @IDPF_VC_XN_IDLE: not expecting a reply, ready to be used
 * @IDPF_VC_XN_WAITING: expecting a reply, not yet received
 * @IDPF_VC_XN_COMPLETED_SUCCESS: a reply was expected and received,
 *				  buffer updated
 * @IDPF_VC_XN_COMPLETED_FAILED: a reply was expected and received, but there
 *				 was an error, buffer not updated
 * @IDPF_VC_XN_SHUTDOWN: transaction object cannot be used, VC torn down
 * @IDPF_VC_XN_ASYNC: transaction sent asynchronously and doesn't have the
 *		      return context; a callback may be provided to handle
 *		      return
 */
enum idpf_vc_xn_state {
	IDPF_VC_XN_IDLE = 1,
	IDPF_VC_XN_WAITING,
	IDPF_VC_XN_COMPLETED_SUCCESS,
	IDPF_VC_XN_COMPLETED_FAILED,
	IDPF_VC_XN_SHUTDOWN,
	IDPF_VC_XN_ASYNC,
};

struct idpf_vc_xn;
/* Callback for asynchronous messages */
typedef int (*async_vc_cb) (void *, struct idpf_vc_xn *,
			    const struct idpf_ctlq_msg *);

/**
 * struct idpf_vc_xn - Data structure representing virtchnl transactions
 * @completed: virtchnl event loop uses that to signal when a reply is
 *	       available, uses kernel completion API
 * @state: virtchnl event loop stores the data below, protected by the
 *	   completion's lock.
 * @reply_sz: Original size of reply, may be > reply_buf.iov_len; it will be
 *	      truncated on its way to the receiver thread according to
 *	      reply_buf.iov_len.
 * @reply: Reference to the buffer(s) where the reply data should be written
 *	   to. May be 0-length (then NULL address permitted) if the reply data
 *	   should be ignored.
 * @async_handler: if sent asynchronously, a callback can be provided to handle
 *		   the reply when it's received
 * @vc_op: corresponding opcode sent with this transaction
 * @idx: index used as retrieval on reply receive, used for cookie
 * @salt: changed every message to make unique, used for cookie
 */
struct idpf_vc_xn {
	struct completion completed;
	enum idpf_vc_xn_state state;
	size_t reply_sz;
	struct kvec reply;
	async_vc_cb async_handler;
	void *async_ctx;
	u32 vc_op;
	u8 idx;
	u8 salt;
};

/**
 * struct idpf_vc_xn_manager - Manager for tracking transactions
 * @ring: backing and lookup for transactions
 * @free_xn_bm: bitmap for free transactions
 * @xn_bm_lock: make bitmap access synchronous where necessary
 * @salt: used to make cookie unique every message
 */
struct idpf_vc_xn_manager {
	struct idpf_vc_xn ring[IDPF_VC_XN_RING_LEN];
	DECLARE_BITMAP(free_xn_bm, IDPF_VC_XN_RING_LEN);
	spinlock_t xn_bm_lock;
	u8 salt;
};

/**
 * struct idpf_vc_xn_params - Parameters for executing transaction
 * @send_buf: kvec for send buffer
 * @recv_buf: kvec for recv buffer, may be NULL, must then have zero length
 * @timeout_ms: timeout to wait for reply
 * @async: send message asynchronously, will not wait on completion
 * @async_handler: If sent asynchronously, optional callback handler. The user
 *		   must be careful when using async handlers as the memory for
 *		   the recv_buf _cannot_ be on stack if this is async.
 * @vc_op: virtchnl op to send
 */
struct idpf_vc_xn_params {
	struct kvec send_buf;
	struct kvec recv_buf;
	int timeout_ms;
	bool async;
	async_vc_cb async_handler;
	void *async_ctx;
	u32 vc_op;
};

/**
 * enum idpf_vport_type
 * @IDPF_DEFAULT_VPORT: Default vport
 * @IDPF_DYNAMIC_VPORT: Dynamic vport
 */
enum idpf_vport_type {
	IDPF_DEFAULT_VPORT = 1,
	IDPF_DYNAMIC_VPORT
};

/**
 * struct idpf_vector_info - Utility structure to pass function arguments as a
 *			     structure
 * @num_req_vecs: Vectors required based on the number of queues updated by the
 *		  user via ethtool
 * @num_curr_vecs: Current number of vectors, must be >= @num_req_vecs
 * @index: Relative starting index for vectors
 * @default_vport: Vectors are for default vport
 */
struct idpf_vector_info {
	u16 num_req_vecs;
	u16 num_curr_vecs;
	u16 index;
	bool default_vport;
};

/**
 * struct idpf_intr_reg
 * @dyn_ctl: Dynamic control interrupt register
 * @dyn_ctl_intena_m: Mask for dyn_ctl interrupt enable
 * @dyn_ctl_itridx_s: Register bit offset for ITR index
 * @dyn_ctl_itridx_m: Mask for ITR index
 * @dyn_ctl_intrvl_s: Register bit offset for ITR interval
 * @rx_itr: RX ITR register
 * @tx_itr: TX ITR register
 * @icr_ena: Interrupt cause register offset
 * @icr_ena_ctlq_m: Mask for ICR
 */
struct idpf_intr_reg {
	void __iomem *dyn_ctl;
	u32 dyn_ctl_intena_m;
	u32 dyn_ctl_itridx_s;
	u32 dyn_ctl_itridx_m;
	u32 dyn_ctl_intrvl_s;
	void __iomem *rx_itr;
	void __iomem *tx_itr;
	void __iomem *icr_ena;
	u32 icr_ena_ctlq_m;
};

/**
 * struct idpf_q_vector
 * @vport: Vport back pointer
 * @affinity_mask: CPU affinity mask
 * @napi: napi handler
 * @v_idx: Vector index
 * @intr_reg: See struct idpf_intr_reg
 * @num_txq: Number of TX queues
 * @tx: Array of TX queues to service
 * @tx_dim: Data for TX net_dim algorithm
 * @tx_itr_value: TX interrupt throttling rate
 * @tx_intr_mode: Dynamic ITR or not
 * @tx_itr_idx: TX ITR index
 * @num_rxq: Number of RX queues
 * @rx: Array of RX queues to service
 * @rx_dim: Data for RX net_dim algorithm
 * @rx_itr_value: RX interrupt throttling rate
 * @rx_intr_mode: Dynamic ITR or not
 * @rx_itr_idx: RX ITR index
 * @num_bufq: Number of buffer queues
 * @bufq: Array of buffer queues to service
 * @total_events: Number of interrupts processed
 * @name: Queue vector name
 */
struct idpf_q_vector {
	struct idpf_vport *vport;
	cpumask_t affinity_mask;
	struct napi_struct napi;
	u16 v_idx;
	struct idpf_intr_reg intr_reg;

	u16 num_txq;
	struct idpf_queue **tx;
	struct dim tx_dim;
	u16 tx_itr_value;
	bool tx_intr_mode;
	u32 tx_itr_idx;

	u16 num_rxq;
	struct idpf_queue **rx;
	struct dim rx_dim;
	u16 rx_itr_value;
	bool rx_intr_mode;
	u32 rx_itr_idx;

	u16 num_bufq;
	struct idpf_queue **bufq;

	u16 total_events;
	char *name;
};

/**
 * struct idpf_max_q - Queue limits
 * @max_rxq: Maximum number of RX queues supported
 * @max_txq: Maixmum number of TX queues supported
 * @max_bufq: In splitq, maximum number of buffer queues supported
 * @max_complq: In splitq, maximum number of completion queues supported
 */
struct idpf_max_q {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/**
 * enum idpf_cap_field - Offsets into capabilities struct for specific caps
 * @IDPF_BASE_CAPS: generic base capabilities
 * @IDPF_CSUM_CAPS: checksum offload capabilities
 * @IDPF_SEG_CAPS: segmentation offload capabilities
 * @IDPF_RSS_CAPS: RSS offload capabilities
 * @IDPF_HSPLIT_CAPS: Header split capabilities
 * @IDPF_RSC_CAPS: RSC offload capabilities
 * @IDPF_OTHER_CAPS: miscellaneous offloads
 *
 * Used when checking for a specific capability flag since different capability
 * sets are not mutually exclusive numerically, the caller must specify which
 * type of capability they are checking for.
 */
enum idpf_cap_field {
	IDPF_BASE_CAPS		= -1,
	IDPF_CSUM_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   csum_caps),
	IDPF_SEG_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   seg_caps),
	IDPF_RSS_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rss_caps),
	IDPF_HSPLIT_CAPS	= offsetof(struct virtchnl2_get_capabilities,
					   hsplit_caps),
	IDPF_RSC_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rsc_caps),
	IDPF_OTHER_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   other_caps),
};

/**
 * idpf_is_capability_ena - Default implementation of capability checking
 * @caps: Capability data
 * @all: all or one flag
 * @field: caps field to check for flags
 * @flag: flag to check
 *
 * Return true if all capabilities are supported, false otherwise
 */
static inline
bool idpf_is_capability_ena(u8 *caps, bool all, enum idpf_cap_field field,
			    u64 flag)
{
	u64 *cap_field;

	if (!caps)
		return false;

	if (field == IDPF_BASE_CAPS)
		return false;

	cap_field = (u64 *)(caps + field);

	if (all)
		return (*cap_field & flag) == flag;
	else
		return !!(*cap_field & flag);
}

#define idpf_is_cap_ena(caps, field, flag) \
	idpf_is_capability_ena((u8 *)caps, false, field, flag)
#define idpf_is_cap_ena_all(caps, field, flag) \
	idpf_is_capability_ena((u8 *)caps, true, field, flag)

void idpf_vc_xn_shutdown(struct idpf_vc_xn_manager *vcxn_mngr);

#endif /* !_IDPF_ETH_COMMON_H_ */
