// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include "idpf.h"
#include "idpf_netdev.h"
#include "idpf_virtchnl.h"

/**
 * idpf_recv_event_msg - Receive virtchnl event message
 * @adapter: Driver specific private structure
 * @ctlq_msg: message to copy from
 *
 * Receive virtchnl event message
 */
static void idpf_recv_event_msg(struct idpf_adapter *adapter,
				struct idpf_ctlq_msg *ctlq_msg)
{
	int payload_size = ctlq_msg->ctx.indirect.payload->size;
	struct virtchnl2_event *v2e;
	u32 event;

	if (payload_size < sizeof(*v2e)) {
		dev_err_ratelimited(&adapter->pdev->dev, "Failed to receive valid payload for event msg (op %d len %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode,
				    payload_size);
		return;
	}

	v2e = (struct virtchnl2_event *)ctlq_msg->ctx.indirect.payload->va;
	event = le32_to_cpu(v2e->event);

	switch (event) {
	case VIRTCHNL2_EVENT_LINK_CHANGE:
		idpf_handle_event_link(adapter, v2e);
		return;
	default:
		dev_err(&adapter->pdev->dev,
			"Unknown event %d from PF\n", event);
		break;
	}
}

/**
 * idpf_mb_clean - Reclaim the send mailbox queue entries
 * @adapter: Driver specific private structure
 *
 * Reclaim the send mailbox queue entries to be used to send further messages
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_mb_clean(struct idpf_adapter *adapter)
{
	u16 i, num_q_msg = IDPF_DFLT_MBX_Q_LEN;
	struct idpf_ctlq_msg **q_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	q_msg = kcalloc(num_q_msg, sizeof(struct idpf_ctlq_msg *), GFP_ATOMIC);
	if (!q_msg)
		return -ENOMEM;

	err = idpf_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
	if (err)
		goto err_kfree;

	for (i = 0; i < num_q_msg; i++) {
		if (!q_msg[i])
			continue;
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem)
			dma_free_coherent(&adapter->pdev->dev, dma_mem->size,
					  dma_mem->va, dma_mem->pa);
		kfree(q_msg[i]);
		kfree(dma_mem);
	}

err_kfree:
	kfree(q_msg);

	return err;
}

/**
 * idpf_send_mb_msg - Send message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchnl opcode
 * @msg_size: size of the payload
 * @msg: pointer to buffer holding the payload
 * @cookie: unique SW generated cookie per message
 *
 * Will prepare the control queue message and initiates the send api
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg, u16 cookie)
{
	struct idpf_ctlq_msg *ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	/* If we are here and a reset is detected nothing much can be
	 * done. This thread should silently abort and expected to
	 * be corrected with a new run either by user or driver
	 * flows after reset
	 */
	if (idpf_is_reset_detected(adapter))
		return 0;

	err = idpf_mb_clean(adapter);
	if (err)
		return err;

	ctlq_msg = kzalloc(sizeof(*ctlq_msg), GFP_ATOMIC);
	if (!ctlq_msg)
		return -ENOMEM;

	dma_mem = kzalloc(sizeof(*dma_mem), GFP_ATOMIC);
	if (!dma_mem) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_cp;
	ctlq_msg->func_id = 0;
	ctlq_msg->data_len = msg_size;
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = 0;
	dma_mem->size = IDPF_CTLQ_MAX_BUF_LEN;
	dma_mem->va = dma_alloc_coherent(&adapter->pdev->dev, dma_mem->size,
					 &dma_mem->pa, GFP_ATOMIC);
	if (!dma_mem->va) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}

	/* It's possible we're just sending an opcode but no buffer */
	if (msg && msg_size)
		memcpy(dma_mem->va, msg, msg_size);
	ctlq_msg->ctx.indirect.payload = dma_mem;
	ctlq_msg->ctx.sw_cookie.data = cookie;

	err = idpf_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err)
		goto send_error;

	return 0;

send_error:
	dma_free_coherent(&adapter->pdev->dev, dma_mem->size, dma_mem->va,
			  dma_mem->pa);
dma_alloc_error:
	kfree(dma_mem);
dma_mem_error:
	kfree(ctlq_msg);

	return err;
}

/* API for virtchnl "transaction" support ("xn" for short).
 *
 * We are reusing the completion lock to serialize the accesses to the
 * transaction state for simplicity, but it could be its own separate synchro
 * as well. For now, this API is only used from within a workqueue context;
 * raw_spin_lock() is enough.
 */
/**
 * idpf_vc_xn_lock - Request exclusive access to vc transaction
 * @xn: struct idpf_vc_xn* to access
 */
#define idpf_vc_xn_lock(xn)			\
	raw_spin_lock(&(xn)->completed.wait.lock)

/**
 * idpf_vc_xn_unlock - Release exclusive access to vc transaction
 * @xn: struct idpf_vc_xn* to access
 */
#define idpf_vc_xn_unlock(xn)		\
	raw_spin_unlock(&(xn)->completed.wait.lock)

/**
 * idpf_vc_xn_release_bufs - Release reference to reply buffer(s) and
 * reset the transaction state.
 * @xn: struct idpf_vc_xn to update
 */
static void idpf_vc_xn_release_bufs(struct idpf_vc_xn *xn)
{
	xn->reply.iov_base = NULL;
	xn->reply.iov_len = 0;

	if (xn->state != IDPF_VC_XN_SHUTDOWN)
		xn->state = IDPF_VC_XN_IDLE;
}

/**
 * idpf_vc_xn_init - Initialize virtchnl transaction object
 * @vcxn_mngr: pointer to vc transaction manager struct
 */
static void idpf_vc_xn_init(struct idpf_vc_xn_manager *vcxn_mngr)
{
	int i;

	spin_lock_init(&vcxn_mngr->xn_bm_lock);

	for (i = 0; i < ARRAY_SIZE(vcxn_mngr->ring); i++) {
		struct idpf_vc_xn *xn = &vcxn_mngr->ring[i];

		xn->state = IDPF_VC_XN_IDLE;
		xn->idx = i;
		idpf_vc_xn_release_bufs(xn);
		init_completion(&xn->completed);
	}

	bitmap_fill(vcxn_mngr->free_xn_bm, IDPF_VC_XN_RING_LEN);
}

/**
 * idpf_vc_xn_shutdown - Uninitialize virtchnl transaction object
 * @vcxn_mngr: pointer to vc transaction manager struct
 *
 * All waiting threads will be woken-up and their transaction aborted. Further
 * operations on that object will fail.
 */
static void idpf_vc_xn_shutdown(struct idpf_vc_xn_manager *vcxn_mngr)
{
	int i;

	spin_lock_bh(&vcxn_mngr->xn_bm_lock);
	bitmap_zero(vcxn_mngr->free_xn_bm, IDPF_VC_XN_RING_LEN);
	spin_unlock_bh(&vcxn_mngr->xn_bm_lock);

	for (i = 0; i < ARRAY_SIZE(vcxn_mngr->ring); i++) {
		struct idpf_vc_xn *xn = &vcxn_mngr->ring[i];

		idpf_vc_xn_lock(xn);
		xn->state = IDPF_VC_XN_SHUTDOWN;
		idpf_vc_xn_release_bufs(xn);
		idpf_vc_xn_unlock(xn);
		complete_all(&xn->completed);
	}
}

/**
 * idpf_vc_xn_pop_free - Pop a free transaction from free list
 * @vcxn_mngr: transaction manager to pop from
 *
 * Returns NULL if no free transactions
 */
static
struct idpf_vc_xn *idpf_vc_xn_pop_free(struct idpf_vc_xn_manager *vcxn_mngr)
{
	struct idpf_vc_xn *xn = NULL;
	unsigned long free_idx;

	spin_lock_bh(&vcxn_mngr->xn_bm_lock);
	free_idx = find_first_bit(vcxn_mngr->free_xn_bm, IDPF_VC_XN_RING_LEN);
	if (free_idx == IDPF_VC_XN_RING_LEN)
		goto do_unlock;

	clear_bit(free_idx, vcxn_mngr->free_xn_bm);
	xn = &vcxn_mngr->ring[free_idx];
	xn->salt = vcxn_mngr->salt++;

do_unlock:
	spin_unlock_bh(&vcxn_mngr->xn_bm_lock);

	return xn;
}

/**
 * idpf_vc_xn_push_free - Push a free transaction to free list
 * @vcxn_mngr: transaction manager to push to
 * @xn: transaction to push
 */
static void idpf_vc_xn_push_free(struct idpf_vc_xn_manager *vcxn_mngr,
				 struct idpf_vc_xn *xn)
{
	idpf_vc_xn_release_bufs(xn);
	set_bit(xn->idx, vcxn_mngr->free_xn_bm);
}

/**
 * idpf_vc_xn_exec - Perform a send/recv virtchnl transaction
 * @adapter: driver specific private structure with vcxn_mngr
 * @params: parameters for this particular transaction including
 *   -vc_op: virtchannel operation to send
 *   -send_buf: kvec iov for send buf and len
 *   -recv_buf: kvec iov for recv buf and len (ignored if NULL)
 *   -timeout_ms: timeout waiting for a reply (milliseconds)
 *   -async: don't wait for message reply, will lose caller context
 *   -async_handler: callback to handle async replies
 *
 * @returns >= 0 for success, the size of the initial reply (may or may not be
 * >= @recv_buf.iov_len, but we never overflow @@recv_buf_iov_base). < 0 for
 * error.
 */
ssize_t idpf_vc_xn_exec(struct idpf_adapter *adapter,
			const struct idpf_vc_xn_params *params)
{
	const struct kvec *send_buf = &params->send_buf;
	struct idpf_vc_xn *xn;
	ssize_t retval;
	u16 cookie;

	xn = idpf_vc_xn_pop_free(adapter->vcxn_mngr);
	/* no free transactions available */
	if (!xn)
		return -ENOSPC;

	idpf_vc_xn_lock(xn);
	if (xn->state == IDPF_VC_XN_SHUTDOWN) {
		retval = -ENXIO;
		goto only_unlock;
	} else if (xn->state != IDPF_VC_XN_IDLE) {
		/* We're just going to clobber this transaction even though
		 * it's not IDLE. If we don't reuse it we could theoretically
		 * eventually leak all the free transactions and not be able to
		 * send any messages. At least this way we make an attempt to
		 * remain functional even though something really bad is
		 * happening that's corrupting what was supposed to be free
		 * transactions.
		 */
		WARN_ONCE(1, "There should only be idle transactions in free list (idx %d op %d)\n",
			  xn->idx, xn->vc_op);
	}

	xn->reply = params->recv_buf;
	xn->reply_sz = 0;
	xn->state = params->async ? IDPF_VC_XN_ASYNC : IDPF_VC_XN_WAITING;
	xn->vc_op = params->vc_op;
	xn->async_handler = params->async_handler;
	idpf_vc_xn_unlock(xn);

	if (!params->async)
		reinit_completion(&xn->completed);
	cookie = FIELD_PREP(IDPF_VC_XN_SALT_M, xn->salt) |
		 FIELD_PREP(IDPF_VC_XN_IDX_M, xn->idx);

	retval = idpf_send_mb_msg(adapter, params->vc_op,
				  send_buf->iov_len, send_buf->iov_base,
				  cookie);
	if (retval) {
		idpf_vc_xn_lock(xn);
		goto release_and_unlock;
	}

	if (params->async)
		return 0;

	wait_for_completion_timeout(&xn->completed,
				    msecs_to_jiffies(params->timeout_ms));

	/* No need to check the return value; we check the final state of the
	 * transaction below. It's possible the transaction actually gets more
	 * timeout than specified if we get preempted here but after
	 * wait_for_completion_timeout returns. This should be non-issue
	 * however.
	 */
	idpf_vc_xn_lock(xn);
	switch (xn->state) {
	case IDPF_VC_XN_SHUTDOWN:
		retval = -ENXIO;
		goto only_unlock;
	case IDPF_VC_XN_WAITING:
		dev_notice_ratelimited(&adapter->pdev->dev, "Transaction timed-out (op %d, %dms)\n",
				       params->vc_op, params->timeout_ms);
		retval = -ETIME;
		break;
	case IDPF_VC_XN_COMPLETED_SUCCESS:
		retval = xn->reply_sz;
		break;
	case IDPF_VC_XN_COMPLETED_FAILED:
		dev_notice_ratelimited(&adapter->pdev->dev, "Transaction failed (op %d)\n",
				       params->vc_op);
		retval = -EIO;
		break;
	default:
		/* Invalid state. */
		WARN_ON_ONCE(1);
		retval = -EIO;
		break;
	}

release_and_unlock:
	idpf_vc_xn_push_free(adapter->vcxn_mngr, xn);
	/* If we receive a VC reply after here, it will be dropped. */
only_unlock:
	idpf_vc_xn_unlock(xn);

	return retval;
}

/**
 * idpf_vc_xn_forward_async - Handle async reply receives
 * @adapter: private data struct
 * @xn: transaction to handle
 * @ctlq_msg: corresponding ctlq_msg
 *
 * For async sends we're going to lose the caller's context so, if an
 * async_handler was provided, it can deal with the reply, otherwise we'll just
 * check and report if there is an error.
 */
static int
idpf_vc_xn_forward_async(struct idpf_adapter *adapter, struct idpf_vc_xn *xn,
			 const struct idpf_ctlq_msg *ctlq_msg)
{
	int err = 0;

	if (ctlq_msg->cookie.mbx.chnl_opcode != xn->vc_op) {
		dev_err_ratelimited(&adapter->pdev->dev, "Async message opcode does not match transaction opcode (msg: %d) (xn: %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode, xn->vc_op);
		xn->reply_sz = 0;
		err = -EINVAL;
		goto release_bufs;
	}

	if (xn->async_handler) {
		err = xn->async_handler(adapter, xn, ctlq_msg);
		goto release_bufs;
	}

	if (ctlq_msg->cookie.mbx.chnl_retval) {
		xn->reply_sz = 0;
		dev_err_ratelimited(&adapter->pdev->dev, "Async message failure (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		err = -EINVAL;
	}

release_bufs:
	idpf_vc_xn_push_free(adapter->vcxn_mngr, xn);

	return err;
}

/**
 * idpf_vc_xn_forward_reply - copy a reply back to receiving thread
 * @adapter: driver specific private structure with vcxn_mngr
 * @ctlq_msg: controlq message to send back to receiving thread
 */
static int
idpf_vc_xn_forward_reply(struct idpf_adapter *adapter,
			 const struct idpf_ctlq_msg *ctlq_msg)
{
	const void *payload = NULL;
	size_t payload_size = 0;
	struct idpf_vc_xn *xn;
	u16 msg_info;
	int err = 0;
	u16 xn_idx;
	u16 salt;

	msg_info = ctlq_msg->ctx.sw_cookie.data;
	xn_idx = FIELD_GET(IDPF_VC_XN_IDX_M, msg_info);
	if (xn_idx >= ARRAY_SIZE(adapter->vcxn_mngr->ring)) {
		dev_err_ratelimited(&adapter->pdev->dev, "Out of bounds cookie received: %02x\n",
				    xn_idx);
		return -EINVAL;
	}
	xn = &adapter->vcxn_mngr->ring[xn_idx];
	salt = FIELD_GET(IDPF_VC_XN_SALT_M, msg_info);
	if (xn->salt != salt) {
		dev_err_ratelimited(&adapter->pdev->dev, "Transaction salt does not match (%02x != %02x)\n",
				    xn->salt, salt);
		return -EINVAL;
	}

	idpf_vc_xn_lock(xn);
	switch (xn->state) {
	case IDPF_VC_XN_WAITING:
		/* success */
		break;
	case IDPF_VC_XN_IDLE:
		dev_err_ratelimited(&adapter->pdev->dev, "Unexpected or belated VC reply (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		err = -EINVAL;
		goto out_unlock;
	case IDPF_VC_XN_SHUTDOWN:
		/* ENXIO is a bit special here as the recv msg loop uses that
		 * know if it should stop trying to clean the ring if we lost
		 * the virtchnl. We need to stop playing with registers and
		 * yield.
		 */
		err = -ENXIO;
		goto out_unlock;
	case IDPF_VC_XN_ASYNC:
		err = idpf_vc_xn_forward_async(adapter, xn, ctlq_msg);
		idpf_vc_xn_unlock(xn);
		return err;
	default:
		dev_err_ratelimited(&adapter->pdev->dev, "Overwriting VC reply (op %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode);
		err = -EBUSY;
		goto out_unlock;
	}

	if (ctlq_msg->cookie.mbx.chnl_opcode != xn->vc_op) {
		dev_err_ratelimited(&adapter->pdev->dev, "Message opcode does not match transaction opcode (msg: %d) (xn: %d)\n",
				    ctlq_msg->cookie.mbx.chnl_opcode, xn->vc_op);
		xn->reply_sz = 0;
		xn->state = IDPF_VC_XN_COMPLETED_FAILED;
		err = -EINVAL;
		goto out_unlock;
	}

	if (ctlq_msg->cookie.mbx.chnl_retval) {
		xn->reply_sz = 0;
		xn->state = IDPF_VC_XN_COMPLETED_FAILED;
		err = -EINVAL;
		goto out_unlock;
	}

	if (ctlq_msg->data_len) {
		payload = ctlq_msg->ctx.indirect.payload->va;
		payload_size = ctlq_msg->ctx.indirect.payload->size;
	}

	xn->reply_sz = payload_size;
	xn->state = IDPF_VC_XN_COMPLETED_SUCCESS;

	if (xn->reply.iov_base && xn->reply.iov_len && payload_size)
		memcpy(xn->reply.iov_base, payload,
		       min_t(size_t, xn->reply.iov_len, payload_size));

out_unlock:
	idpf_vc_xn_unlock(xn);
	/* we _cannot_ hold lock while calling complete */
	complete(&xn->completed);

	return err;
}

/**
 * idpf_recv_mb_msg - Receive message over mailbox
 * @adapter: Driver specific private structure
 *
 * Will receive control queue message and posts the receive buffer. Returns 0
 * on success and negative on failure.
 */
int idpf_recv_mb_msg(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_msg ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int post_err, err;
	u16 num_recv;

	while (1) {
		/* This will get <= num_recv messages and output how many
		 * actually received on num_recv.
		 */
		num_recv = 1;
		err = idpf_ctlq_recv(adapter->hw.arq, &num_recv, &ctlq_msg);
		if (err || !num_recv)
			break;

		if (ctlq_msg.data_len) {
			dma_mem = ctlq_msg.ctx.indirect.payload;
		} else {
			dma_mem = NULL;
			num_recv = 0;
		}

		if (ctlq_msg.cookie.mbx.chnl_opcode == VIRTCHNL2_OP_EVENT)
			idpf_recv_event_msg(adapter, &ctlq_msg);
		else
			err = idpf_vc_xn_forward_reply(adapter, &ctlq_msg);

		post_err = idpf_ctlq_post_rx_buffs(&adapter->hw,
						   adapter->hw.arq,
						   &num_recv, &dma_mem);

		/* If post failed clear the only buffer we supplied */
		if (post_err) {
			if (dma_mem)
				dmam_free_coherent(&adapter->pdev->dev,
						   dma_mem->size, dma_mem->va,
						   dma_mem->pa);
			break;
		}

		/* virtchnl trying to shutdown, stop cleaning */
		if (err == -ENXIO)
			break;
	}

	return err;
}

/**
 * idpf_send_ver_msg - send virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl version message.  Returns 0 on success, negative on failure.
 */
static int idpf_send_ver_msg(struct idpf_adapter *adapter)
{
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_version_info vvi;
	ssize_t reply_sz;
	u32 major, minor;
	int err = 0;

	if (adapter->virt_ver_maj) {
		vvi.major = cpu_to_le32(adapter->virt_ver_maj);
		vvi.minor = cpu_to_le32(adapter->virt_ver_min);
	} else {
		vvi.major = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MAJOR);
		vvi.minor = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MINOR);
	}

	xn_params.vc_op = VIRTCHNL2_OP_VERSION;
	xn_params.send_buf.iov_base = &vvi;
	xn_params.send_buf.iov_len = sizeof(vvi);
	xn_params.recv_buf = xn_params.send_buf;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(vvi))
		return -EIO;

	major = le32_to_cpu(vvi.major);
	minor = le32_to_cpu(vvi.minor);

	if (major > IDPF_VIRTCHNL_VERSION_MAJOR) {
		dev_warn(&adapter->pdev->dev, "Virtchnl major version greater than supported\n");
		return -EINVAL;
	}

	if (major == IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor > IDPF_VIRTCHNL_VERSION_MINOR)
		dev_warn(&adapter->pdev->dev, "Virtchnl minor version didn't match\n");

	/* If we have a mismatch, resend version to update receiver on what
	 * version we will use.
	 */
	if (!adapter->virt_ver_maj &&
	    major != IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor != IDPF_VIRTCHNL_VERSION_MINOR)
		err = -EAGAIN;

	adapter->virt_ver_maj = major;
	adapter->virt_ver_min = minor;

	return err;
}

/**
 * idpf_send_get_caps_msg - Send virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_get_caps_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities caps = {};
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;

	caps.csum_caps =
		cpu_to_le32(VIRTCHNL2_CAP_TX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_GENERIC);

	caps.seg_caps =
		cpu_to_le32(VIRTCHNL2_CAP_SEG_IPV4_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV4_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV4_SCTP		|
			    VIRTCHNL2_CAP_SEG_IPV6_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV6_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV6_SCTP		|
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL);

	caps.rss_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RSS_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV4_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV4_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV4_OTHER	|
			    VIRTCHNL2_CAP_RSS_IPV6_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV6_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV6_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV6_OTHER);

	caps.hsplit_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6);

	caps.rsc_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RSC_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSC_IPV6_TCP);

	caps.other_caps =
		cpu_to_le64(VIRTCHNL2_CAP_SRIOV			|
			    VIRTCHNL2_CAP_MACFILTER		|
			    VIRTCHNL2_CAP_SPLITQ_QSCHED		|
			    VIRTCHNL2_CAP_PROMISC		|
			    VIRTCHNL2_CAP_LOOPBACK);

	xn_params.vc_op = VIRTCHNL2_OP_GET_CAPS;
	xn_params.send_buf.iov_base = &caps;
	xn_params.send_buf.iov_len = sizeof(caps);
	xn_params.recv_buf.iov_base = &adapter->caps;
	xn_params.recv_buf.iov_len = sizeof(adapter->caps);
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;

	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;
	if (reply_sz < sizeof(adapter->caps))
		return -EIO;

	return 0;
}

/**
 * idpf_vport_alloc_max_qs - Allocate max queues for a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;
	u16 default_vports = idpf_get_default_vports(adapter);
	int max_rx_q, max_tx_q;

	mutex_lock(&adapter->queue_lock);

	max_rx_q = le16_to_cpu(caps->max_rx_q) / default_vports;
	max_tx_q = le16_to_cpu(caps->max_tx_q) / default_vports;
	if (adapter->num_alloc_vports < default_vports) {
		max_q->max_rxq = min_t(u16, max_rx_q, IDPF_MAX_Q);
		max_q->max_txq = min_t(u16, max_tx_q, IDPF_MAX_Q);
	} else {
		max_q->max_rxq = IDPF_MIN_Q;
		max_q->max_txq = IDPF_MIN_Q;
	}
	max_q->max_bufq = max_q->max_rxq * IDPF_MAX_BUFQS_PER_RXQ_GRP;
	max_q->max_complq = max_q->max_txq;

	if (avail_queues->avail_rxq < max_q->max_rxq ||
	    avail_queues->avail_txq < max_q->max_txq ||
	    avail_queues->avail_bufq < max_q->max_bufq ||
	    avail_queues->avail_complq < max_q->max_complq) {
		mutex_unlock(&adapter->queue_lock);

		return -EINVAL;
	}

	avail_queues->avail_rxq -= max_q->max_rxq;
	avail_queues->avail_txq -= max_q->max_txq;
	avail_queues->avail_bufq -= max_q->max_bufq;
	avail_queues->avail_complq -= max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);

	return 0;
}

/**
 * idpf_vport_dealloc_max_qs - Deallocate max queues of a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues;

	mutex_lock(&adapter->queue_lock);
	avail_queues = &adapter->avail_queues;

	avail_queues->avail_rxq += max_q->max_rxq;
	avail_queues->avail_txq += max_q->max_txq;
	avail_queues->avail_bufq += max_q->max_bufq;
	avail_queues->avail_complq += max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);
}

/**
 * idpf_init_avail_queues - Initialize available queues on the device
 * @adapter: Driver specific private structure
 */
static void idpf_init_avail_queues(struct idpf_adapter *adapter)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;

	avail_queues->avail_rxq = le16_to_cpu(caps->max_rx_q);
	avail_queues->avail_txq = le16_to_cpu(caps->max_tx_q);
	avail_queues->avail_bufq = le16_to_cpu(caps->max_rx_bufq);
	avail_queues->avail_complq = le16_to_cpu(caps->max_tx_complq);
}

/**
 * idpf_get_reg_intr_vecs - Get vector queue register offset
 * @vport: virtual port structure
 * @reg_vals: Register offsets to store in
 *
 * Returns number of registers that got populated
 */
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals)
{
	struct virtchnl2_vector_chunks *chunks;
	struct idpf_vec_regs reg_val;
	u16 num_vchunks, num_vec;
	int num_regs = 0, i, j;

	chunks = &vport->adapter->req_vec_chunks->vchunks;
	num_vchunks = le16_to_cpu(chunks->num_vchunks);

	for (j = 0; j < num_vchunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u32 dynctl_reg_spacing;
		u32 itrn_reg_spacing;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		reg_val.dyn_ctl_reg = le32_to_cpu(chunk->dynctl_reg_start);
		reg_val.itrn_reg = le32_to_cpu(chunk->itrn_reg_start);
		reg_val.itrn_index_spacing = le32_to_cpu(chunk->itrn_index_spacing);

		dynctl_reg_spacing = le32_to_cpu(chunk->dynctl_reg_spacing);
		itrn_reg_spacing = le32_to_cpu(chunk->itrn_reg_spacing);

		for (i = 0; i < num_vec; i++) {
			reg_vals[num_regs].dyn_ctl_reg = reg_val.dyn_ctl_reg;
			reg_vals[num_regs].itrn_reg = reg_val.itrn_reg;
			reg_vals[num_regs].itrn_index_spacing =
						reg_val.itrn_index_spacing;

			reg_val.dyn_ctl_reg += dynctl_reg_spacing;
			reg_val.itrn_reg += itrn_reg_spacing;
			num_regs++;
		}
	}

	return num_regs;
}

/**
 * idpf_send_alloc_vectors_msg - Send virtchnl alloc vectors message
 * @adapter: Driver specific private structure
 * @num_vectors: number of vectors to be allocated
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors)
{
	struct virtchnl2_alloc_vectors *rcvd_vec __free(kfree) = NULL;
	struct idpf_vc_xn_params xn_params = {};
	struct virtchnl2_alloc_vectors ac = {};
	ssize_t reply_sz;
	u16 num_vchunks;
	int size;

	ac.num_vectors = cpu_to_le16(num_vectors);

	rcvd_vec = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!rcvd_vec)
		return -ENOMEM;

	xn_params.vc_op = VIRTCHNL2_OP_ALLOC_VECTORS;
	xn_params.send_buf.iov_base = &ac;
	xn_params.send_buf.iov_len = sizeof(ac);
	xn_params.recv_buf.iov_base = rcvd_vec;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;

	num_vchunks = le16_to_cpu(rcvd_vec->vchunks.num_vchunks);
	size = struct_size(rcvd_vec, vchunks.vchunks, num_vchunks);
	if (reply_sz < size)
		return -EIO;

	if (size > IDPF_CTLQ_MAX_BUF_LEN)
		return -EINVAL;

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = kmemdup(rcvd_vec, size, GFP_KERNEL);
	if (!adapter->req_vec_chunks)
		return -ENOMEM;

	if (le16_to_cpu(adapter->req_vec_chunks->num_vectors) < num_vectors) {
		kfree(adapter->req_vec_chunks);
		adapter->req_vec_chunks = NULL;
		return -EINVAL;
	}

	return 0;
}

/**
 * idpf_send_dealloc_vectors_msg - Send virtchnl de allocate vectors message
 * @adapter: Driver specific private structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_alloc_vectors *ac = adapter->req_vec_chunks;
	struct virtchnl2_vector_chunks *vcs = &ac->vchunks;
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;
	int buf_size;

	buf_size = struct_size(vcs, vchunks, le16_to_cpu(vcs->num_vchunks));

	xn_params.vc_op = VIRTCHNL2_OP_DEALLOC_VECTORS;
	xn_params.send_buf.iov_base = vcs;
	xn_params.send_buf.iov_len = buf_size;
	xn_params.timeout_ms = IDPF_VC_XN_MIN_TIMEOUT_MSEC;
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0)
		return reply_sz;

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;

	return 0;
}

/**
 * idpf_get_max_vfs - Get max number of vfs supported
 * @adapter: Driver specific private structure
 *
 * Returns max number of VFs
 */
static int idpf_get_max_vfs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_sriov_vfs);
}

/**
 * idpf_send_set_sriov_vfs_msg - Send virtchnl set sriov vfs message
 * @adapter: Driver specific private structure
 * @num_vfs: number of virtual functions to be created
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs)
{
	struct virtchnl2_sriov_vfs_info svi = {};
	struct idpf_vc_xn_params xn_params = {};
	ssize_t reply_sz;

	svi.num_vfs = cpu_to_le16(num_vfs);
	xn_params.vc_op = VIRTCHNL2_OP_SET_SRIOV_VFS;
	xn_params.timeout_ms = IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC;
	xn_params.send_buf.iov_base = &svi;
	xn_params.send_buf.iov_len = sizeof(svi);
	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);

	return reply_sz < 0 ? reply_sz : 0;
}

/**
 * idpf_find_ctlq - Given a type and id, find ctlq info
 * @hw: hardware struct
 * @type: type of ctrlq to find
 * @id: ctlq id to find
 *
 * Returns pointer to found ctlq info struct, NULL otherwise.
 */
static struct idpf_ctlq_info *idpf_find_ctlq(struct idpf_hw *hw,
					     enum idpf_ctlq_type type, int id)
{
	struct idpf_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		if (cq->q_id == id && cq->cq_type == type)
			return cq;

	return NULL;
}

/**
 * idpf_init_dflt_mbx - Setup default mailbox parameters and make request
 * @adapter: adapter info struct
 *
 * Returns 0 on success, negative otherwise
 */
int idpf_init_dflt_mbx(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_create_info ctlq_info[] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		},
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		}
	};
	struct idpf_hw *hw = &adapter->hw;
	int err;

	adapter->dev_ops.reg_ops.ctlq_reg_init(ctlq_info);

	err = idpf_ctlq_init(hw, IDPF_NUM_DFLT_MBX_Q, ctlq_info);
	if (err)
		return err;

	hw->asq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_TX,
				 IDPF_DFLT_MBX_ID);
	hw->arq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_RX,
				 IDPF_DFLT_MBX_ID);

	if (!hw->asq || !hw->arq) {
		idpf_ctlq_deinit(hw);

		return -ENOENT;
	}

	adapter->state = __IDPF_VER_CHECK;

	return 0;
}

/**
 * idpf_deinit_dflt_mbx - Free up ctlqs setup
 * @adapter: Driver specific private data structure
 */
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter)
{
	if (adapter->hw.arq && adapter->hw.asq) {
		idpf_mb_clean(adapter);
		idpf_ctlq_deinit(&adapter->hw);
	}
	adapter->hw.arq = NULL;
	adapter->hw.asq = NULL;
}

/**
 * idpf_vport_params_buf_rel - Release memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will release memory to hold the vport parameters received on MailBox
 */
static void idpf_vport_params_buf_rel(struct idpf_adapter *adapter)
{
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
}

/**
 * idpf_vport_params_buf_alloc - Allocate memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will alloc memory to hold the vport parameters received on MailBox
 */
static int idpf_vport_params_buf_alloc(struct idpf_adapter *adapter)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);

	adapter->vport_params_reqd = kcalloc(num_max_vports,
					     sizeof(*adapter->vport_params_reqd),
					     GFP_KERNEL);
	if (!adapter->vport_params_reqd)
		return -ENOMEM;

	adapter->vport_params_recvd = kcalloc(num_max_vports,
					      sizeof(*adapter->vport_params_recvd),
					      GFP_KERNEL);
	if (!adapter->vport_params_recvd)
		goto err_mem;

	adapter->vport_ids = kcalloc(num_max_vports, sizeof(u32), GFP_KERNEL);
	if (!adapter->vport_ids)
		goto err_mem;

	if (adapter->vport_config)
		return 0;

	adapter->vport_config = kcalloc(num_max_vports,
					sizeof(*adapter->vport_config),
					GFP_KERNEL);
	if (!adapter->vport_config)
		goto err_mem;

	return 0;

err_mem:
	idpf_vport_params_buf_rel(adapter);

	return -ENOMEM;
}

/**
 * idpf_vc_core_init - Initialize state machine and get driver specific
 * resources
 * @adapter: Driver specific private structure
 *
 * This function will initialize the state machine and request all necessary
 * resources required by the device driver. Once the state machine is
 * initialized, allocate memory to store vport specific information and also
 * requests required interrupts.
 *
 * Returns 0 on success, -EAGAIN function will get called again,
 * otherwise negative on failure.
 */
int idpf_vc_core_init(struct idpf_adapter *adapter)
{
	int task_delay = 30;
	u16 num_max_vports;
	int err = 0;

	if (!adapter->vcxn_mngr) {
		adapter->vcxn_mngr = kzalloc(sizeof(*adapter->vcxn_mngr), GFP_KERNEL);
		if (!adapter->vcxn_mngr) {
			err = -ENOMEM;
			goto init_failed;
		}
	}
	idpf_vc_xn_init(adapter->vcxn_mngr);

	while (adapter->state != __IDPF_INIT_SW) {
		switch (adapter->state) {
		case __IDPF_VER_CHECK:
			err = idpf_send_ver_msg(adapter);
			switch (err) {
			case 0:
				/* success, move state machine forward */
				adapter->state = __IDPF_GET_CAPS;
				fallthrough;
			case -EAGAIN:
				goto restart;
			default:
				/* Something bad happened, try again but only a
				 * few times.
				 */
				goto init_failed;
			}
		case __IDPF_GET_CAPS:
			err = idpf_send_get_caps_msg(adapter);
			if (err)
				goto init_failed;
			adapter->state = __IDPF_INIT_SW;
			break;
		default:
			dev_err(&adapter->pdev->dev, "Device is in bad state: %d\n",
				adapter->state);
			err = -EINVAL;
			goto init_failed;
		}
		break;
restart:
		/* Give enough time before proceeding further with
		 * state machine
		 */
		msleep(task_delay);
	}

	pci_sriov_set_totalvfs(adapter->pdev, idpf_get_max_vfs(adapter));
	num_max_vports = idpf_get_max_vports(adapter);
	adapter->max_vports = num_max_vports;
	adapter->vports = kcalloc(num_max_vports, sizeof(*adapter->vports),
				  GFP_KERNEL);
	if (!adapter->vports)
		return -ENOMEM;

	if (!adapter->netdevs) {
		adapter->netdevs = kcalloc(num_max_vports,
					   sizeof(struct net_device *),
					   GFP_KERNEL);
		if (!adapter->netdevs) {
			err = -ENOMEM;
			goto err_netdev_alloc;
		}
	}

	err = idpf_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to alloc vport params buffer: %d\n",
			err);
		goto err_netdev_alloc;
	}

	/* Start the mailbox task before requesting vectors. This will ensure
	 * vector information response from mailbox is handled
	 */
	queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task, 0);

	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	err = idpf_intr_req(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "failed to enable interrupt vectors: %d\n",
			err);
		goto err_intr_req;
	}

	idpf_init_avail_queues(adapter);

	/* Skew the delay for init tasks for each function based on fn number
	 * to prevent every function from making the same call simultaneously.
	 */
	queue_delayed_work(adapter->init_wq, &adapter->init_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	set_bit(IDPF_VC_CORE_INIT, adapter->flags);

	return 0;

err_intr_req:
	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->mbx_task);
	idpf_vport_params_buf_rel(adapter);
err_netdev_alloc:
	kfree(adapter->vports);
	adapter->vports = NULL;
	return err;

init_failed:
	/* Don't retry if we're trying to go down, just bail. */
	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return err;

	if (++adapter->mb_wait_count > IDPF_MB_MAX_ERR) {
		dev_err(&adapter->pdev->dev, "Failed to establish mailbox communications with hardware\n");

		return -EFAULT;
	}
	/* If it reached here, it is possible that mailbox queue initialization
	 * register writes might not have taken effect. Retry to initialize
	 * the mailbox again
	 */
	adapter->state = __IDPF_VER_CHECK;
	if (adapter->vcxn_mngr)
		idpf_vc_xn_shutdown(adapter->vcxn_mngr);
	idpf_deinit_dflt_mbx(adapter);
	set_bit(IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(task_delay));

	return -EAGAIN;
}

/**
 * idpf_vc_core_deinit - Device deinit routine
 * @adapter: Driver specific private structure
 *
 */
void idpf_vc_core_deinit(struct idpf_adapter *adapter)
{
	if (!test_bit(IDPF_VC_CORE_INIT, adapter->flags))
		return;

	idpf_vc_xn_shutdown(adapter->vcxn_mngr);
	idpf_deinit_task(adapter);
	idpf_intr_rel(adapter);

	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->mbx_task);

	idpf_vport_params_buf_rel(adapter);

	kfree(adapter->vports);
	adapter->vports = NULL;

	clear_bit(IDPF_VC_CORE_INIT, adapter->flags);
}

/**
 * idpf_get_vec_ids - Initialize vector id from Mailbox parameters
 * @adapter: adapter structure to get the mailbox vector id
 * @vecids: Array of vector ids
 * @num_vecids: number of vector ids
 * @chunks: vector ids received over mailbox
 *
 * Will initialize the mailbox vector id which is received from the
 * get capabilities and data queue vector ids with ids received as
 * mailbox parameters.
 * Returns number of ids filled
 */
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_vchunks);
	int num_vecid_filled = 0;
	int i, j;

	vecids[num_vecid_filled] = adapter->mb_vector.v_idx;
	num_vecid_filled++;

	for (j = 0; j < num_chunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u16 start_vecid, num_vec;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		start_vecid = le16_to_cpu(chunk->start_vector_id);

		for (i = 0; i < num_vec; i++) {
			if ((num_vecid_filled + i) < num_vecids) {
				vecids[num_vecid_filled + i] = start_vecid;
				start_vecid++;
			} else {
				break;
			}
		}
		num_vecid_filled = num_vecid_filled + i;
	}

	return num_vecid_filled;
}

/**
 * idpf_is_capability_ena - Default implementation of capability checking
 * @adapter: Private data struct
 * @all: all or one flag
 * @field: caps field to check for flags
 * @flag: flag to check
 *
 * Return true if all capabilities are supported, false otherwise
 */
bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag)
{
	u8 *caps = (u8 *)&adapter->caps;
	u32 *cap_field;

	if (!caps)
		return false;

	if (field == IDPF_BASE_CAPS)
		return false;

	cap_field = (u32 *)(caps + field);

	if (all)
		return (*cap_field & flag) == flag;
	else
		return !!(*cap_field & flag);
}

/**
 * idpf_get_vport_id: Get vport id
 * @vport: virtual port structure
 *
 * Return vport id from the adapter persistent data
 */
u32 idpf_get_vport_id(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_msg;

	vport_msg = vport->adapter->vport_params_recvd[vport->idx];

	return le32_to_cpu(vport_msg->vport_id);
}
