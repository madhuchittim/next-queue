// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/libeth_virtchnl.h>

/**
 * libeth_init_xn_send_buf - Initialize send buf information
 * @xn_params: xn transaction buffer
 * @send_buf: send buffer 
 * @send_buf_size: send buffer size
 */
static 
void libeth_init_xn_send_buf(struct libeth_ctlq_xn_send_params *xn_params,
			     void *send_buf, size_t send_buf_size)
{
	xn_params->send_buf.iov_base = send_buf;
	xn_params->send_buf.iov_len = send_buf_size;
	xn_params->ctlq_msg->data_len = send_buf_size;
}

/**
 * libeth_init_xn_params - Initialize xn transaction data
 * @xn_params: Transaction buffer to be initialized
 * @msg_param: pointer to virtchnl message info
 * @ctlq_msg: pointer to control queue message
 */
static void
libeth_init_xn_params(struct libeth_ctlq_xn_send_params *xn_params,
		      struct libeth_virtchnl_msg_param *msg_param,
		      struct libeth_ctlq_msg *ctlq_msg)
{
	xn_params->hw = msg_param->hw;
	xn_params->xnm = msg_param->xnm;
	xn_params->ctlq_info = msg_param->ctlq_info;
	xn_params->ctlq_msg = ctlq_msg;

	xn_params->timeout_ms = (msg_param->msg->timeout_ms) ?
				 msg_param->msg->timeout_ms :
				 LIBETH_CTRL_SQ_CMD_TIMEOUT;
	xn_params->recv_buf = msg_param->msg->recv_buf;
	xn_params->async_resp_cb = msg_param->msg->async_resp_cb;
	xn_params->ctx = msg_param->msg->ctx;

	return;
}

/**
 * libeth_init_ctlq_msg - Initialize control queue message
 * @ctlq_msg: control queue message to be initialized
 * @hw_opcode: HW opcode
 * @mbox_chnl_op: virtchnl2 command
 * @mbox_ret: return value
 * @data_len: message length
 */
static void
libeth_init_ctlq_msg(struct libeth_ctlq_msg *ctlq_msg,
		     u16 hw_opcode, u16 mbox_chnl_op, u16 mbox_ret,
		     u16 data_len)
{
	ctlq_msg->opcode = hw_opcode;
	ctlq_msg->cookie.mbx.chnl_opcode = mbox_chnl_op;
	ctlq_msg->cookie.mbx.chnl_retval = mbox_ret;
	ctlq_msg->data_len = data_len;

	return;
}

/**
 * libeth_send_virtchnl_msg - Virtchnl message handler
 * @msg_param: pointer to virtchnl message info
 */
int libeth_send_virtchnl_msg(struct libeth_virtchnl_msg_param *msg_param)
{
	struct libeth_ctlq_xn_send_params xn_params = { };
	struct libeth_ctlq_msg *ctlq_msg;
	struct libeth_virtchnl_msg *msg;
	u16 virtchnl_opcode, data_len;
	int err;

	if (!msg_param || !msg_param->msg)
		return -EINVAL;
	
	ctlq_msg = kzalloc(sizeof(*ctlq_msg), GFP_KERNEL);
	if (!ctlq_msg)
		return -ENOMEM;

	msg = msg_param->msg;
	virtchnl_opcode = msg_param->msg->virtchnl_opcode;
	data_len =  msg_param->msg->send_buf.iov_len;
	libeth_init_xn_params(&xn_params, msg_param, ctlq_msg);
	libeth_init_ctlq_msg(ctlq_msg, msg_param->msg->hw_opcode,
			     virtchnl_opcode, 0, data_len);
	libeth_init_xn_send_buf(&xn_params, (void *)msg->send_buf.iov_base,
				msg->send_buf.iov_len);

	switch(virtchnl_opcode) {
		case VIRTCHNL2_OP_VERSION:
		case VIRTCHNL2_OP_GET_CAPS:
		case VIRTCHNL2_OP_RESET_VF:
		case VIRTCHNL2_OP_CREATE_VPORT:
		case VIRTCHNL2_OP_DESTROY_VPORT:
			err = libeth_ctlq_xn_send(&xn_params);
		break;
		
		default:
			kfree(ctlq_msg);
			err = -EINVAL;
		break;
	}
	

	return err;
}
EXPORT_SYMBOL_NS_GPL(libeth_send_virtchnl_msg, LIBETH);

/**
 * libeth_send_clean - cleanup the send control queue message buffers
 * @params: pointer to params struct
 */
int libeth_send_clean(struct libeth_ctlq_xn_clean_params *params)
{
	int i, ret = 0;

	ret = libeth_ctlq_xn_send_clean(params);
	if (!ret) {
		for (i = 0; i < params->num_msgs; i++)
			kfree(params->q_msg[i]);
	}

	return ret;
}
EXPORT_SYMBOL_NS_GPL(libeth_send_clean, LIBETH);

