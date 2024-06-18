/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _LIBETH_CONTROLQ_H_
#define _LIBETH_CONTROLQ_H_

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/bitfield.h>

#include <net/virtchnl2.h>
#include "libeth_mem.h"

/**
 * struct libeth_hw - structure for key hardware information
 * @num_regions: number of active regions in mmio space
 * @mem_regions: array of mmio region info
 * @pdev: pci device struct
 * @cq_list_head: list storing all the control queues
 */
struct libeth_hw {
	u16 num_regions;
#define LIBETH_MMIO_REGION_MAX_NUM	16
	struct libeth_mmio_region mem_regions[LIBETH_MMIO_REGION_MAX_NUM];
	struct pci_dev *pdev;
	struct list_head cq_list_head;
};

/**
 * struct libeth_ctlq_reg - controlq register structure
 * @head: head of the queue
 * @tail: tail of the queue
 * @len: size of the queue
 * @bah: base address high
 * @bal: base address low
 * @len_mask: length mask
 * @len_ena_mask: length enable mask
 * @head_mask: head mask
 */
struct libeth_ctlq_reg {
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
	u32 len_mask;
	u32 len_ena_mask;
	u32 head_mask;
};

/**
 * struct libeth_ctlq_msg - control queue message data
 * @vmvf_type: represents the source of the message on recv
 * @host_id: 3b field used only when sending a message to CP
 * @opcode: hardware opcode
 * @data_len: size of the payload
 * @func_id: function identifier
 * @status: received message status
 * @chnl_opcode: software opcode
 * @chnl_retval: return data on receive
 * @direct: Direct context
 * @context: context for indirect message
 * @payload: payload to be sent
 * @rsvd: reserved
 * @data: software cookie data
 * @flags: software cookie flags
 */
struct libeth_ctlq_msg {
	u8 vmvf_type; /* represents the source of the message on recv */
#define LIBETH_VMVF_TYPE_VF 0
#define LIBETH_VMVF_TYPE_VM 1
#define LIBETH_VMVF_TYPE_PF 2
	u8 host_id;
#define LIBETH_HOST_ID_MASK 0x7
	u16 opcode;
	u16 data_len;
	union {
		u16 func_id;
		u16 status;
	};
	union {
		struct {
			u32 chnl_opcode;
			u32 chnl_retval;
		} mbx;
	} cookie;
	union {
#define LIBETH_DIRECT_CTX_SIZE	16
#define LIBETH_INDIRECT_CTX_SIZE	8
		u8 direct[LIBETH_DIRECT_CTX_SIZE];
		struct {
			u8 context[LIBETH_INDIRECT_CTX_SIZE];
			struct libeth_dma_mem *payload;
		} indirect;
		struct {
			u32 rsvd;
			u16 data;
			u16 flags;
		} sw_cookie;
	} ctx;
};

/**
 * struct libeth_ctlq_create_info - control queue create information
 * @id: absolute queue offset passed as input. -1 for default mailbox
 * @len: queue length passed as input
 * @buf_size: buffer size passed as input
 * @base_address: output, HPA of the queue start
 * @reg: registers accessed by control queues
 */
struct libeth_ctlq_create_info {
	enum virtchnl2_queue_type type;
	int id;
	u16 len;
	u16 buf_size;
	u64 base_address;
	struct libeth_ctlq_reg reg;
};

/**
 * struct libeth_ctlq_info - control queue information
 * @cq_list: control queue list
 * @cq_type: control queue type
 * @q_id: queue identifier
 * @cq_lock: control queue lock
 * @next_to_use: next available slot to send buffer
 * @next_to_clean: next descrtiptor to be cleaned
 * @next_to_post: next available slot to post buffers to after receive
 * @desc_ring: descrtiptor ring memory
 * @rx_buff: rx buffers posted to hardware
 * @tx_msg: tx messages sent to hardware
 * @buf_size: queue buffer size
 * @ring_size: number of descriptors
 * @reg: registers used by control queues
 */
struct libeth_ctlq_info {
	struct list_head cq_list;
	enum virtchnl2_queue_type cq_type;
/* Mailbox control queue id is -1 */
#define LIBETH_CTLQ_MBOX_ID	-1
	int q_id;
	struct mutex cq_lock;
	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_post;
	struct libeth_dma_mem desc_ring;
	union {
		struct libeth_dma_mem **rx_buff;
		struct libeth_ctlq_msg **tx_msg;
	} bi;
	u16 buf_size;
	u16 ring_size;
	struct libeth_ctlq_reg reg;
};

/**
 * enum libeth_mbx_opc - PF/VF mailbox commands
 * @libeth_mbq_opc_send_msg_to_cp: used by PF or VF to send a message to its CP
 */
enum libeth_mbx_opc {
	libeth_mbq_opc_send_msg_to_cp		= 0x0801,
};

/* Maximum buffer length for all control queue types */
#define LIBETH_CTLQ_MAX_BUF_LEN	4096

#define LIBETH_CTLQ_DESC(R, i) \
	(&(((struct libeth_ctlq_desc *)((R)->desc_ring.va))[i]))

#define LIBETH_CTLQ_DESC_UNUSED(R) \
	((u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->ring_size) + \
	       (R)->next_to_clean - (R)->next_to_use - 1))

#define LIBETH_DESC_MARKED_DONE(x) (le16_to_cpu(x->flags) & LIBETH_CTLQ_FLAG_DD)

/* Control Queue default settings */
#define LIBETH_CTRL_SQ_CMD_TIMEOUT	250  /* msecs */

/**
 * struct libeth_ctlq_desc - control queue descriptor format
 * @flags: control queue descriptor flags
 * @opcode: hardware opcode
 * @datalen: size of the payload
 * @ret_val: return value on recieve
 * @pfid_vfid: host pci function identifier
 * @v_opcode_dtype: software opcode[27:0] dytpe[31:28]
 * @v_retval: retrun value on recieve
 * @param0: direct data
 * @param1: direct data
 * @param2: direct data
 * @param3: direct data
 * @param0: indirect data
 * @sw_cookie: indirect software cookie
 * @v_flags: indirect flags
 * @addr_high: indirect address high
 * @addr_low: indirect address low
 * @raw: direct data
 */
struct libeth_ctlq_desc {
	__le16 flags;
	__le16 opcode;
	__le16 datalen;
	union {
		__le16 ret_val;
		__le16 pfid_vfid;
#define LIBETH_CTLQ_DESC_VF_ID_S	0
#define LIBETH_CTLQ_DESC_VF_ID_M	(0x7FF << LIBETH_CTLQ_DESC_VF_ID_S)
#define LIBETH_CTLQ_DESC_PF_ID_S	11
#define LIBETH_CTLQ_DESC_PF_ID_M	(0x1F << LIBETH_CTLQ_DESC_PF_ID_S)
	};
	__le32 v_opcode_dtype;
	__le32 v_retval;
	union {
		struct {
			__le32 param0;
			__le32 param1;
			__le32 param2;
			__le32 param3;
		} direct;
		struct {
			__le32 param0;
			__le16 sw_cookie;
			__le16 v_flags;
			__le32 addr_high;
			__le32 addr_low;
		} indirect;
		u8 raw[16];
	} params;
};

/* Flags sub-structure
 * |0  |1  |2  |3  |4  |5  |6  |7  |8  |9  |10 |11 |12 |13 |14 |15 |
 * |DD |CMP|ERR|  * RSV *  |FTYPE  | *RSV* |RD |VFC|BUF|  HOST_ID  |
 */
/* command flags and offsets */
#define LIBETH_CTLQ_FLAG_DD_S		0
#define LIBETH_CTLQ_FLAG_CMP_S		1
#define LIBETH_CTLQ_FLAG_ERR_S		2
#define LIBETH_CTLQ_FLAG_FTYPE_S		6
#define LIBETH_CTLQ_FLAG_RD_S		10
#define LIBETH_CTLQ_FLAG_VFC_S		11
#define LIBETH_CTLQ_FLAG_BUF_S		12
#define LIBETH_CTLQ_FLAG_HOST_ID_S	13

#define LIBETH_CTLQ_FLAG_DD	BIT(LIBETH_CTLQ_FLAG_DD_S)	/* 0x1	  */
#define LIBETH_CTLQ_FLAG_CMP	BIT(LIBETH_CTLQ_FLAG_CMP_S)	/* 0x2	  */
#define LIBETH_CTLQ_FLAG_ERR	BIT(LIBETH_CTLQ_FLAG_ERR_S)	/* 0x4	  */
#define LIBETH_CTLQ_FLAG_FTYPE_VM	BIT(LIBETH_CTLQ_FLAG_FTYPE_S)	/* 0x40	  */
#define LIBETH_CTLQ_FLAG_FTYPE_PF	BIT(LIBETH_CTLQ_FLAG_FTYPE_S + 1)	/* 0x80   */
#define LIBETH_CTLQ_FLAG_RD	BIT(LIBETH_CTLQ_FLAG_RD_S)	/* 0x400  */
#define LIBETH_CTLQ_FLAG_VFC	BIT(LIBETH_CTLQ_FLAG_VFC_S)	/* 0x800  */
#define LIBETH_CTLQ_FLAG_BUF	BIT(LIBETH_CTLQ_FLAG_BUF_S)	/* 0x1000 */

/* Host ID is a special field that has 3b and not a 1b flag */
#define LIBETH_CTLQ_FLAG_HOST_ID_M MAKE_MASK(0x7000UL, LIBETH_CTLQ_FLAG_HOST_ID_S)

int libeth_ctlq_init(struct libeth_hw *hw, u8 num_q,
		   struct libeth_ctlq_create_info *q_info);

/* Allocate and initialize a single control queue, which will be added to the
 * control queue list; returns a handle to the created control queue
 */
int libeth_ctlq_add(struct libeth_hw *hw,
		  struct libeth_ctlq_create_info *qinfo,
		  struct libeth_ctlq_info **cq);

/* Deinitialize and deallocate a single control queue */
void libeth_ctlq_remove(struct libeth_hw *hw,
		      struct libeth_ctlq_info *cq);

/* Sends messages to HW and will also free the buffer*/
int libeth_ctlq_send(struct libeth_hw *hw,
		   struct libeth_ctlq_info *cq,
		   u16 num_q_msg,
		   struct libeth_ctlq_msg q_msg[]);

/* Receives messages and called by interrupt handler/polling
 * initiated by app/process. Also caller is supposed to free the buffers
 */
int libeth_ctlq_recv(struct libeth_ctlq_info *cq, u16 *num_q_msg,
		   struct libeth_ctlq_msg *q_msg);

/* Reclaims send descriptors on HW write back */
int libeth_ctlq_clean_sq(struct libeth_ctlq_info *cq, u16 *clean_count,
		       struct libeth_ctlq_msg *msg_status[], bool force);

/* Indicate RX buffers are done being processed */
int libeth_ctlq_post_rx_buffs(struct libeth_hw *hw,
			    struct libeth_ctlq_info *cq,
			    u16 *buff_count,
			    struct libeth_dma_mem **buffs);

/* Will destroy all q including the default mb */
void libeth_ctlq_deinit(struct libeth_hw *hw);

#define LIBETH_CTLQ_MAX_XN_ENTRIES	256
#define LIBETH_CTLQ_XN_INDEX_M	GENMASK(7, 0)
#define LIBETH_CTLQ_XN_COOKIE_M	GENMASK(15, 8)

typedef int (*async_ctlq_resp_cb) (void *ctx, void *resp, size_t resp_len,
				   int status);
typedef int (*default_ctlq_msg_handler) (struct libeth_hw*,
					 struct libeth_ctlq_msg *ctlq_msg);
/**
 * enum libeth_ctlq_xn_state - supported xn states
 * LIBETH_CTLQ_XN_IDLE: No transaction is pending
 * LIBETH_CTLQ_XN_WAITING: waiting for transaction to complete
 * LIBETH_CTLQ_XN_COMPLETED_SUCCESS: transaction completed with success
 * LIBETH_CTLQ_XN_COMPLETED_FAILED: transaction completed with failure
 * LIBETH_CTLQ_XN_SHUTDOWN: xn is about to be deinitialized
 * LIBETH_CTLQ_XN_ASYNC: transaction is an async type
 */
enum libeth_ctlq_xn_state {
	LIBETH_CTLQ_XN_IDLE = 1,
	LIBETH_CTLQ_XN_WAITING,
	LIBETH_CTLQ_XN_COMPLETED_SUCCESS,
	LIBETH_CTLQ_XN_COMPLETED_FAILED,
	LIBETH_CTLQ_XN_SHUTDOWN,
	LIBETH_CTLQ_XN_ASYNC,
};

/**
 * struct libeth_ctlq_xn - Data structure representing virtchnl transactions
 * @cookie: changed every message to make unique, used for cookie
 * @index: index used as retrieval on reply receive, used for cookie
 * @virtchnl_opcode: virtchanl command opcode used for xn transaction
 * @recv_buf: Reference to the buffer(s) where the reply data should be written
 *	   to. May be 0-length (then NULL address permitted) if the reply data
 *	   should be ignored.
 * @data_len: number of bytes copied into response buffer
 * @lock: lock that protects the xn variables
 * @state: virtchnl event loop stores the xn state, protected by the lock.
 * @send_ctlq_info: virtchnl control queue information.
 * @cmd_completion_event: virtchnl event loop uses that to signal when a reply
 *	       is available, uses kernel completion API
 * @dma_mem: dma memory for virtchnl transaction.
 * @ctx: context for call back function
 * @async_resp_cb: if sent asynchronously, a callback can be provided to handle
 *		   the reply when it's received
 */
struct libeth_ctlq_xn {
	u8 cookie;
	u8 index;
	u32 virtchnl_opcode;
	struct kvec recv_buf;
	size_t data_len;
	spinlock_t lock;
	enum libeth_ctlq_xn_state	state;
	struct libeth_ctlq_info *send_ctlq_info;
	struct completion cmd_completion_event;
	struct libeth_dma_mem *dma_mem;
	void *ctx;
	async_ctlq_resp_cb async_resp_cb;
};

/**
 * struct libeth_ctlq_xn_manager - Data structure representing xn transactions
 * @cookie: changed every message to make unique, used for cookie
 * @free_xns_bm_lock: lock that protects the free xns bit map
 * @free_xns_bm: bitmap that represents the free xns indexes
 * @ring: Array of xn entries for virtchnl transactions
 */
struct libeth_ctlq_xn_manager {
	u8	cookie;
	spinlock_t free_xns_bm_lock;
	DECLARE_BITMAP(free_xns_bm, LIBETH_CTLQ_MAX_XN_ENTRIES);
	struct libeth_ctlq_xn	ring[LIBETH_CTLQ_MAX_XN_ENTRIES];
};

/**
 * struct libeth_ctlq_xn_send_params - Data structure used for virtchnl xn
 *	send transaction
 * @hw: device access data
 * @xnm: xn manager to process xn entries
 * @ctlq_info: virtchnl control queue information
 * @ctlq_msg: virtchnl control queue message information
 * @send_buf: Represents the buffer that carries outgoing information
 * @recv_buf: Reference to the buffer(s) where the reply data should be written
 * @data_len: number of bytes copied into response buffer
 * @timeout_ms: Virtchanl tranaction timeout in mili seconds
 * @ctx: context for call back function
 * @async_resp_cb: if sent asynchronously, a callback can be provided to handle
 *		   the reply when it's received
 */
struct libeth_ctlq_xn_send_params {
	struct libeth_hw *hw;
	struct libeth_ctlq_xn_manager *xnm;
	struct libeth_ctlq_info *ctlq_info;
	struct libeth_ctlq_msg *ctlq_msg;
	struct kvec send_buf;
	struct kvec recv_buf;
	size_t data_len;
	u64 timeout_ms;
	void *ctx;
	async_ctlq_resp_cb async_resp_cb;
};

/**
 * struct libeth_ctlq_xn_recv_params - Data structure used for virtchnl xn
 *	receive transaction
 * @xnm: xn manager to process xn entries
 * @hw: device access data
 * @ctlq_info: virtchnl control queue information
 * @default_msg_handler: A callback handles a message originated from the peer
 */
struct libeth_ctlq_xn_recv_params {
	struct libeth_ctlq_xn_manager *xnm;
	struct libeth_hw *hw;
	struct libeth_ctlq_info *ctlq_info;
	default_ctlq_msg_handler	default_msg_handler;
};

/**
 * struct libeth_ctlq_xn_clean_params - Data structure used for cleaning the
 *	control queue messages
 * @force: force the cleaning
 * @num_msgs: number of messages to be cleaned
 * @hw: device access data
 * @ctlq_info: virtchnl control queue information
 * @q_msg: A buffer carries the cleaned messages
 */
struct libeth_ctlq_xn_clean_params {
	bool	force;
	u16	num_msgs;
	struct libeth_hw *hw;
	struct libeth_ctlq_info *ctlq_info;
	struct libeth_ctlq_msg **q_msg;
};

/**
 * struct libeth_ctlq_xn_init_params - Data structure used for initialzing the
 *	xn transaction manager
 * @num_qs: number of control queues needs to initialized for virtchnl
 *		 transactions
 * @cctlq_info: virtchnl control queue information
 * @hw: device access data
 * @xnm: xn manager to process xn entries
 */
struct libeth_ctlq_xn_init_params {
	u8	num_qs;
	struct libeth_ctlq_create_info *cctlq_info;
	struct libeth_hw *hw;
	struct libeth_ctlq_xn_manager *xnm;
};

int libeth_ctlq_xn_init(struct libeth_ctlq_xn_init_params *params);
int libeth_ctlq_xn_deinit(struct libeth_ctlq_xn_init_params *params);

int libeth_ctlq_xn_send(struct libeth_ctlq_xn_send_params *params);
int libeth_ctlq_xn_recv(struct libeth_ctlq_xn_recv_params *params);
int libeth_ctlq_xn_send_clean(struct libeth_ctlq_xn_clean_params *params);
#endif /* _LIBETH_CONTROLQ_H_ */
