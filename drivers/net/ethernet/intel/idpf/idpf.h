/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_H_
#define _IDPF_H_

/* Forward declaration */
struct idpf_adapter;
enum idpf_vport_reset_cause;

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
#include "idpf_lan_txrx.h"
#include "idpf_vport.h"
#include "idpf_controlq.h"

#define GETMAXVAL(num_bits)		GENMASK((num_bits) - 1, 0)

#define IDPF_NO_FREE_SLOT		0xffff

/* Default Mailbox settings */
#define IDPF_NUM_DFLT_MBX_Q		2	/* includes both TX and RX */
#define IDPF_DFLT_MBX_Q_LEN		64
#define IDPF_DFLT_MBX_ID		-1
/* maximum number of times to try before resetting mailbox */
#define IDPF_MB_MAX_ERR			20
#define IDPF_NUM_CHUNKS_PER_MSG(struct_sz, chunk_sz)	\
	((IDPF_CTLQ_MAX_BUF_LEN - (struct_sz)) / (chunk_sz))

#define IDPF_MAX_WAIT			500

/* available message levels */
#define IDPF_AVAIL_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define IDPF_VIRTCHNL_VERSION_MAJOR VIRTCHNL2_VERSION_MAJOR_2
#define IDPF_VIRTCHNL_VERSION_MINOR VIRTCHNL2_VERSION_MINOR_0

/**
 * enum idpf_state - State machine to handle bring up
 * @__IDPF_VER_CHECK: Negotiate virtchnl version
 * @__IDPF_GET_CAPS: Negotiate capabilities
 * @__IDPF_INIT_SW: Init based on given capabilities
 * @__IDPF_STATE_LAST: Must be last, used to determine size
 */
enum idpf_state {
	__IDPF_VER_CHECK,
	__IDPF_GET_CAPS,
	__IDPF_INIT_SW,
	__IDPF_STATE_LAST,
};

/**
 * enum idpf_flags - Hard reset causes.
 * @IDPF_HR_FUNC_RESET: Hard reset when TxRx timeout
 * @IDPF_HR_DRV_LOAD: Set on driver load for a clean HW
 * @IDPF_HR_RESET_IN_PROG: Reset in progress
 * @IDPF_REMOVE_IN_PROG: Driver remove in progress
 * @IDPF_MB_INTR_MODE: Mailbox in interrupt mode
 * @IDPF_VC_CORE_INIT: virtchnl core has been init
 * @IDPF_FLAGS_NBITS: Must be last
 */
enum idpf_flags {
	IDPF_HR_FUNC_RESET,
	IDPF_HR_DRV_LOAD,
	IDPF_HR_RESET_IN_PROG,
	IDPF_REMOVE_IN_PROG,
	IDPF_MB_INTR_MODE,
	IDPF_VC_CORE_INIT,
	IDPF_FLAGS_NBITS,
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
 * struct idpf_reset_reg - Reset register offsets/masks
 * @rstat: Reset status register
 * @rstat_m: Reset status mask
 */
struct idpf_reset_reg {
	void __iomem *rstat;
	u32 rstat_m;
};

/**
 * struct idpf_reg_ops - Device specific register operation function pointers
 * @ctlq_reg_init: Mailbox control queue register initialization
 * @intr_reg_init: Traffic interrupt register initialization
 * @mb_intr_reg_init: Mailbox interrupt register initialization
 * @reset_reg_init: Reset register initialization
 * @trigger_reset: Trigger a reset to occur
 */
struct idpf_reg_ops {
	void (*ctlq_reg_init)(struct idpf_ctlq_create_info *cq);
	int (*intr_reg_init)(struct idpf_vport *vport);
	void (*mb_intr_reg_init)(struct idpf_adapter *adapter);
	void (*reset_reg_init)(struct idpf_adapter *adapter);
	void (*trigger_reset)(struct idpf_adapter *adapter,
			      enum idpf_flags trig_cause);
};

/**
 * struct idpf_dev_ops - Device specific operations
 * @reg_ops: Register operations
 */
struct idpf_dev_ops {
	struct idpf_reg_ops reg_ops;
};

/**
 * enum idpf_vport_reset_cause - Vport soft reset causes
 * @IDPF_SR_Q_CHANGE: Soft reset queue change
 * @IDPF_SR_Q_DESC_CHANGE: Soft reset descriptor change
 * @IDPF_SR_MTU_CHANGE: Soft reset MTU change
 * @IDPF_SR_RSC_CHANGE: Soft reset RSC change
 */
enum idpf_vport_reset_cause {
	IDPF_SR_Q_CHANGE,
	IDPF_SR_Q_DESC_CHANGE,
	IDPF_SR_MTU_CHANGE,
	IDPF_SR_RSC_CHANGE,
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
 * struct idpf_vector_lifo - Stack to maintain vector indexes used for vector
 *			     distribution algorithm
 * @top: Points to stack top i.e. next available vector index
 * @base: Always points to start of the free pool
 * @size: Total size of the vector stack
 * @vec_idx: Array to store all the vector indexes
 *
 * Vector stack maintains all the relative vector indexes at the *adapter*
 * level. This stack is divided into 2 parts, first one is called as 'default
 * pool' and other one is called 'free pool'.  Vector distribution algorithm
 * gives priority to default vports in a way that at least IDPF_MIN_Q_VEC
 * vectors are allocated per default vport and the relative vector indexes for
 * those are maintained in default pool. Free pool contains all the unallocated
 * vector indexes which can be allocated on-demand basis. Mailbox vector index
 * is maintained in the default pool of the stack.
 */
struct idpf_vector_lifo {
	u16 top;
	u16 base;
	u16 size;
	u16 *vec_idx;
};

struct idpf_vc_xn_manager;

/**
 * struct idpf_adapter - Device data struct generated on probe
 * @pdev: PCI device struct given on probe
 * @virt_ver_maj: Virtchnl version major
 * @virt_ver_min: Virtchnl version minor
 * @msg_enable: Debug message level enabled
 * @mb_wait_count: Number of times mailbox was attempted initialization
 * @state: Init state machine
 * @flags: See enum idpf_flags
 * @reset_reg: See struct idpf_reset_reg
 * @hw: Device access data
 * @num_req_msix: Requested number of MSIX vectors
 * @num_avail_msix: Available number of MSIX vectors
 * @num_msix_entries: Number of entries in MSIX table
 * @msix_entries: MSIX table
 * @req_vec_chunks: Requested vector chunk data
 * @mb_vector: Mailbox vector data
 * @vector_stack: Stack to store the msix vector indexes
 * @irq_mb_handler: Handler for hard interrupt for mailbox
 * @tx_timeout_count: Number of TX timeouts that have occurred
 * @avail_queues: Device given queue limits
 * @vports: Array to store vports created by the driver
 * @netdevs: Associated Vport netdevs
 * @vport_params_reqd: Vport params requested
 * @vport_params_recvd: Vport params received
 * @vport_ids: Array of device given vport identifiers
 * @vport_config: Vport config parameters
 * @max_vports: Maximum vports that can be allocated
 * @num_alloc_vports: Current number of vports allocated
 * @next_vport: Next free slot in pf->vport[] - 0-based!
 * @init_task: Initialization task
 * @init_wq: Workqueue for initialization task
 * @serv_task: Periodically recurring maintenance task
 * @serv_wq: Workqueue for service task
 * @mbx_task: Task to handle mailbox interrupts
 * @mbx_wq: Workqueue for mailbox responses
 * @vc_event_task: Task to handle out of band virtchnl event notifications
 * @vc_event_wq: Workqueue for virtchnl events
 * @stats_task: Periodic statistics retrieval task
 * @stats_wq: Workqueue for statistics task
 * @caps: Negotiated capabilities with device
 * @vcxn_mngr: Virtchnl transaction manager
 * @dev_ops: See idpf_dev_ops
 * @num_vfs: Number of allocated VFs through sysfs. PF does not directly talk
 *	     to VFs but is used to initialize them
 * @crc_enable: Enable CRC insertion offload
 * @req_tx_splitq: TX split or single queue model to request
 * @req_rx_splitq: RX split or single queue model to request
 * @vport_ctrl_lock: Lock to protect the vport control flow
 * @vector_lock: Lock to protect vector distribution
 * @queue_lock: Lock to protect queue distribution
 * @vc_buf_lock: Lock to protect virtchnl buffer
 */
struct idpf_adapter {
	struct pci_dev *pdev;
	u32 virt_ver_maj;
	u32 virt_ver_min;

	u32 msg_enable;
	u32 mb_wait_count;
	enum idpf_state state;
	DECLARE_BITMAP(flags, IDPF_FLAGS_NBITS);
	struct idpf_reset_reg reset_reg;
	struct idpf_hw hw;
	u16 num_req_msix;
	u16 num_avail_msix;
	u16 num_msix_entries;
	struct msix_entry *msix_entries;
	struct virtchnl2_alloc_vectors *req_vec_chunks;
	struct idpf_q_vector mb_vector;
	struct idpf_vector_lifo vector_stack;
	irqreturn_t (*irq_mb_handler)(int irq, void *data);

	u32 tx_timeout_count;
	struct idpf_avail_queue_info avail_queues;
	struct idpf_vport **vports;
	struct net_device **netdevs;
	struct virtchnl2_create_vport **vport_params_reqd;
	struct virtchnl2_create_vport **vport_params_recvd;
	u32 *vport_ids;

	struct idpf_vport_config **vport_config;
	u16 max_vports;
	u16 num_alloc_vports;
	u16 next_vport;

	struct delayed_work init_task;
	struct workqueue_struct *init_wq;
	struct delayed_work serv_task;
	struct workqueue_struct *serv_wq;
	struct delayed_work mbx_task;
	struct workqueue_struct *mbx_wq;
	struct delayed_work vc_event_task;
	struct workqueue_struct *vc_event_wq;
	struct delayed_work stats_task;
	struct workqueue_struct *stats_wq;
	struct virtchnl2_get_capabilities caps;
	struct idpf_vc_xn_manager *vcxn_mngr;

	struct idpf_dev_ops dev_ops;
	int num_vfs;
	bool crc_enable;
	bool req_tx_splitq;
	bool req_rx_splitq;

	struct mutex vport_ctrl_lock;
	struct mutex vector_lock;
	struct mutex queue_lock;
	struct mutex vc_buf_lock;
};

#define idpf_is_cap_ena(adapter, field, flag) \
	idpf_is_capability_ena(adapter, false, field, flag)
#define idpf_is_cap_ena_all(adapter, field, flag) \
	idpf_is_capability_ena(adapter, true, field, flag)

bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag);

/**
 * idpf_get_reserved_vecs - Get reserved vectors
 * @adapter: private data struct
 */
static inline u16 idpf_get_reserved_vecs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.num_allocated_vectors);
}

/**
 * idpf_get_default_vports - Get default number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_default_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.default_num_vports);
}

/**
 * idpf_get_max_vports - Get max number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_max_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_vports);
}

/**
 * idpf_get_max_tx_bufs - Get max scatter-gather buffers supported by the device
 * @adapter: private data struct
 */
static inline unsigned int idpf_get_max_tx_bufs(struct idpf_adapter *adapter)
{
	return adapter->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_get_min_tx_pkt_len - Get min packet length supported by the device
 * @adapter: private data struct
 */
static inline u8 idpf_get_min_tx_pkt_len(struct idpf_adapter *adapter)
{
	u8 pkt_len = adapter->caps.min_sso_packet_len;

	return pkt_len ? pkt_len : IDPF_TX_MIN_PKT_LEN;
}

/**
 * idpf_get_reg_addr - Get BAR0 register address
 * @adapter: private data struct
 * @reg_offset: register offset value
 *
 * Based on the register offset, return the actual BAR0 register address
 */
static inline void __iomem *idpf_get_reg_addr(struct idpf_adapter *adapter,
					      resource_size_t reg_offset)
{
	return (void __iomem *)(adapter->hw.hw_addr + reg_offset);
}

/**
 * idpf_is_reset_detected - check if we were reset at some point
 * @adapter: driver specific private structure
 *
 * Returns true if we are either in reset currently or were previously reset.
 */
static inline bool idpf_is_reset_detected(struct idpf_adapter *adapter)
{
	if (!adapter->hw.arq)
		return true;

	return !(readl(idpf_get_reg_addr(adapter, adapter->hw.arq->reg.len)) &
		 adapter->hw.arq->reg.len_mask);
}

/**
 * idpf_is_reset_in_prog - check if reset is in progress
 * @adapter: driver specific private structure
 *
 * Returns true if hard reset is in progress, false otherwise
 */
static inline bool idpf_is_reset_in_prog(struct idpf_adapter *adapter)
{
	return (test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags) ||
		test_bit(IDPF_HR_FUNC_RESET, adapter->flags) ||
		test_bit(IDPF_HR_DRV_LOAD, adapter->flags));
}

/**
 * idpf_get_max_tx_hdr_size -- get the size of tx header
 * @adapter: Driver specific private structure
 */
static inline u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_tx_hdr_size);
}

void idpf_statistics_task(struct work_struct *work);
void idpf_init_task(struct work_struct *work);
void idpf_service_task(struct work_struct *work);
void idpf_mbx_task(struct work_struct *work);
void idpf_vc_event_task(struct work_struct *work);
void idpf_dev_ops_init(struct idpf_adapter *adapter);
void idpf_vf_dev_ops_init(struct idpf_adapter *adapter);
int idpf_intr_req(struct idpf_adapter *adapter);
void idpf_intr_rel(struct idpf_adapter *adapter);
u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter);
void idpf_deinit_task(struct idpf_adapter *adapter);
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter,
				u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info);
void idpf_set_ethtool_ops(struct net_device *netdev);
void idpf_vport_intr_write_itr(struct idpf_q_vector *q_vector,
			       u16 itr, bool tx);
int idpf_sriov_configure(struct pci_dev *pdev, int num_vfs);

u8 idpf_vport_get_hsplit(const struct idpf_vport *vport);
bool idpf_vport_set_hsplit(const struct idpf_vport *vport, u8 val);
int idpf_vport_manage_rss_lut(struct idpf_vport *vport);
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport);

#endif /* !_IDPF_H_ */
