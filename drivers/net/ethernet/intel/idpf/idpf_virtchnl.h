/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_VIRTCHNL_H_
#define _IDPF_VIRTCHNL_H_

struct idpf_adapter;
struct idpf_netdev_priv;
struct idpf_vec_regs;
struct idpf_vport;
struct idpf_vport_max_q;
struct idpf_vport_user_config_data;

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
typedef int (*async_vc_cb) (struct idpf_adapter *, struct idpf_vc_xn *,
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
	u32 vc_op;
};

ssize_t idpf_vc_xn_exec(struct idpf_adapter *adapter,
			const struct idpf_vc_xn_params *params);

#endif /* _IDPF_VIRTCHNL_H_ */
