/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _LIBETH_VIRTCHNL_H_
#define _LIBETH_VIRTCHNL_H_

#include <net/virtchnl2.h>
#include "libeth_controlq.h"

/**
 * struct libeth_virtchnl_msg - Data structure used for virtchanl message info
 * @ctx: device access data
 * @xnm: xn manager to process xn entries
 * @ctlq_info: virtchnl control queue information
 * @ctlq_msg: virtchnl control queue message information
 * @send_buf: Represents the buffer that carries outgoing information
 * @recv_buf: Reference to the buffer(s) where the reply data should be written
 * @timeout_ms: Virtchanl tranaction timeout in mili seconds
 * @async_resp_cb: if sent asynchronously, a callback can be provided to handle
 *		   the reply when it's received
 */
struct libeth_virtchnl_msg {
	void *ctx;
	u16 hw_opcode;
	u16 virtchnl_opcode;
	struct kvec send_buf;
	struct kvec recv_buf;
	u64 timeout_ms;
	async_ctlq_resp_cb async_resp_cb;
};

/**
 * struct libeth_virtchnl_msg_param - Data structure used for sending
 	virtchanl message
 * @hw: device access data
 * @msg: virtchanl message buffer
 * @ctlq_info: virtchnl control queue information
 * @xnm: xn manager to process xn entries
 */
struct libeth_virtchnl_msg_param {
	struct libeth_hw *hw;
	struct libeth_virtchnl_msg *msg;
	struct libeth_ctlq_info *ctlq_info;
	struct libeth_ctlq_xn_manager *xnm; 
};

int libeth_send_virtchnl_msg(struct libeth_virtchnl_msg_param *msg_param);
int libeth_send_clean(struct libeth_ctlq_xn_clean_params *params);

#endif /* _LIBETH_VIRTCHNL_H_ */
