// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/libeth_controlq.h>

/**
 * libeth_ctlq_alloc_desc_ring - Allocate Control Queue (CQ) rings
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 */
static int libeth_ctlq_alloc_desc_ring(struct libeth_hw *hw,
				       struct libeth_ctlq_info *cq)
{
	size_t size = cq->ring_size * sizeof(struct libeth_ctlq_desc);

	cq->desc_ring.va = libeth_alloc_dma_mem(hw, &cq->desc_ring, size);
	if (!cq->desc_ring.va)
		return -ENOMEM;

	return 0;
}

/**
 * libeth_ctlq_alloc_bufs - Allocate Control Queue (CQ) buffers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Allocate the buffer head for all control queues, and if it's a receive
 * queue, allocate DMA buffers
 */
static int libeth_ctlq_alloc_bufs(struct libeth_hw *hw,
				  struct libeth_ctlq_info *cq)
{
	int i;

	/* Do not allocate DMA buffers for transmit queues */
	if (cq->cq_type == VIRTCHNL2_QUEUE_TYPE_TX)
		return 0;

	/* We'll be allocating the buffer info memory first, then we can
	 * allocate the mapped buffers for the event processing
	 */
	cq->bi.rx_buff = kcalloc(cq->ring_size, sizeof(struct libeth_dma_mem *),
				 GFP_KERNEL);
	if (!cq->bi.rx_buff)
		return -ENOMEM;

	/* allocate the mapped buffers (except for the last one) */
	for (i = 0; i < cq->ring_size - 1; i++) {
		struct libeth_dma_mem *bi;
		int num = 1; /* number of libeth_dma_mem to be allocated */

		cq->bi.rx_buff[i] = kcalloc(num, sizeof(struct libeth_dma_mem),
					    GFP_KERNEL);
		if (!cq->bi.rx_buff[i])
			goto unwind_alloc_cq_bufs;

		bi = cq->bi.rx_buff[i];

		bi->va = libeth_alloc_dma_mem(hw, bi, cq->buf_size);
		if (!bi->va) {
			/* unwind will not free the failed entry */
			kfree(cq->bi.rx_buff[i]);
			goto unwind_alloc_cq_bufs;
		}
	}

	return 0;

unwind_alloc_cq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--) {
		libeth_free_dma_mem(hw, cq->bi.rx_buff[i]);
		kfree(cq->bi.rx_buff[i]);
	}
	kfree(cq->bi.rx_buff);

	return -ENOMEM;
}

/**
 * libeth_ctlq_free_bufs - Free CQ buffer info elements
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the DMA buffers for RX queues, and DMA buffer header for both RX and TX
 * queues.  The upper layers are expected to manage freeing of TX DMA buffers
 */
static void libeth_ctlq_free_bufs(struct libeth_hw *hw,
				  struct libeth_ctlq_info *cq)
{
	void *bi;

	if (cq->cq_type == VIRTCHNL2_QUEUE_TYPE_RX) {
		int i;

		/* free DMA buffers for rx queues*/
		for (i = 0; i < cq->ring_size; i++) {
			if (cq->bi.rx_buff[i]) {
				libeth_free_dma_mem(hw, cq->bi.rx_buff[i]);
				kfree(cq->bi.rx_buff[i]);
			}
		}

		bi = (void *)cq->bi.rx_buff;
	} else {
		bi = (void *)cq->bi.tx_msg;
	}

	/* free the buffer header */
	kfree(bi);
}

/**
 * libeth_ctlq_dealloc_ring_res - Free memory allocated for control queue
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the memory used by the ring, buffers and other related structures
 */
static void libeth_ctlq_dealloc_ring_res(struct libeth_hw *hw,
					 struct libeth_ctlq_info *cq)
{
	/* free ring buffers and the ring itself */
	libeth_ctlq_free_bufs(hw, cq);
	libeth_free_dma_mem(hw, &cq->desc_ring);
}

/**
 * libeth_ctlq_alloc_ring_res - allocate memory for descriptor ring and bufs
 * @hw: pointer to hw struct
 * @cq: pointer to control queue struct
 *
 * Do *NOT* hold cq_lock when calling this as the memory allocation routines
 * called are not going to be atomic context safe
 */
static int libeth_ctlq_alloc_ring_res(struct libeth_hw *hw,
				      struct libeth_ctlq_info *cq)
{
	int err;

	/* allocate the ring memory */
	err = libeth_ctlq_alloc_desc_ring(hw, cq);
	if (err)
		return err;

	/* allocate buffers in the rings */
	err = libeth_ctlq_alloc_bufs(hw, cq);
	if (err)
		goto libeth_init_cq_free_ring;

	/* success! */
	return 0;

libeth_init_cq_free_ring:
	libeth_free_dma_mem(hw, &cq->desc_ring);

	return err;
}

/**
 * libeth_ctlq_setup_regs - initialize control queue registers
 * @cq: pointer to the specific control queue
 * @q_create_info: structs containing info for each queue to be initialized
 */
static void libeth_ctlq_setup_regs(struct libeth_ctlq_info *cq,
				   struct libeth_ctlq_create_info *q_create_info)
{
	/* set control queue registers in our local struct */
	cq->reg.head = q_create_info->reg.head;
	cq->reg.tail = q_create_info->reg.tail;
	cq->reg.len = q_create_info->reg.len;
	cq->reg.bah = q_create_info->reg.bah;
	cq->reg.bal = q_create_info->reg.bal;
	cq->reg.len_mask = q_create_info->reg.len_mask;
	cq->reg.len_ena_mask = q_create_info->reg.len_ena_mask;
	cq->reg.head_mask = q_create_info->reg.head_mask;
}

/**
 * libeth_ctlq_init_regs - Initialize control queue registers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 * @is_rxq: true if receive control queue, false otherwise
 *
 * Initialize registers. The caller is expected to have already initialized the
 * descriptor ring memory and buffer memory
 */
static void libeth_ctlq_init_regs(struct libeth_hw *hw, struct libeth_ctlq_info *cq,
				  bool is_rxq)
{
	/* Update tail to post pre-allocated buffers for rx queues */
	if (is_rxq)
		wr32(hw, cq->reg.tail, (u32)(cq->ring_size - 1));

	/* For non-Mailbox control queues only TAIL need to be set */
	if (cq->q_id != LIBETH_CTLQ_MBOX_ID)
		return;

	/* Clear Head for both send or receive */
	wr32(hw, cq->reg.head, 0);

	/* set starting point */
	wr32(hw, cq->reg.bal, lower_32_bits(cq->desc_ring.pa));
	wr32(hw, cq->reg.bah, upper_32_bits(cq->desc_ring.pa));
	wr32(hw, cq->reg.len, (cq->ring_size | cq->reg.len_ena_mask));
}

/**
 * libeth_ctlq_init_rxq_bufs - populate receive queue descriptors with buf
 * @cq: pointer to the specific Control queue
 *
 * Record the address of the receive queue DMA buffers in the descriptors.
 * The buffers must have been previously allocated.
 */
static void libeth_ctlq_init_rxq_bufs(struct libeth_ctlq_info *cq)
{
	int i;

	for (i = 0; i < cq->ring_size; i++) {
		struct libeth_ctlq_desc *desc = LIBETH_CTLQ_DESC(cq, i);
		struct libeth_dma_mem *bi = cq->bi.rx_buff[i];

		/* No buffer to post to descriptor, continue */
		if (!bi)
			continue;

		desc->flags =
			cpu_to_le16(LIBETH_CTLQ_FLAG_BUF | LIBETH_CTLQ_FLAG_RD);
		desc->opcode = 0;
		desc->datalen = cpu_to_le16(bi->size);
		desc->ret_val = 0;
		desc->v_opcode_dtype = 0;
		desc->v_retval = 0;
		desc->params.indirect.addr_high =
			cpu_to_le32(upper_32_bits(bi->pa));
		desc->params.indirect.addr_low =
			cpu_to_le32(lower_32_bits(bi->pa));
		desc->params.indirect.param0 = 0;
		desc->params.indirect.sw_cookie = 0;
		desc->params.indirect.v_flags = 0;
	}
}

/**
 * libeth_ctlq_shutdown - shutdown the CQ
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * The main shutdown routine for any controq queue
 */
static void libeth_ctlq_shutdown(struct libeth_hw *hw,
				 struct libeth_ctlq_info *cq)
{
	mutex_lock(&cq->cq_lock);

	/* free ring buffers and the ring itself */
	libeth_ctlq_dealloc_ring_res(hw, cq);

	/* Set ring_size to 0 to indicate uninitialized queue */
	cq->ring_size = 0;

	mutex_unlock(&cq->cq_lock);
	mutex_destroy(&cq->cq_lock);
}

/**
 * libeth_ctlq_add - add one control queue
 * @hw: pointer to hardware struct
 * @qinfo: info for queue to be created
 * @cq_out: (output) double pointer to control queue to be created
 *
 * Allocate and initialize a control queue and add it to the control queue list.
 * The cq parameter will be allocated/initialized and passed back to the caller
 * if no errors occur.
 *
 * Note: libeth_ctlq_init must be called prior to any calls to libeth_ctlq_add
 */
int libeth_ctlq_add(struct libeth_hw *hw,
		    struct libeth_ctlq_create_info *qinfo,
		    struct libeth_ctlq_info **cq_out)
{
	struct libeth_ctlq_info *cq;
	bool is_rxq = false;
	int err;

	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq)
		return -ENOMEM;

	cq->cq_type = qinfo->type;
	cq->q_id = qinfo->id;
	cq->buf_size = qinfo->buf_size;
	cq->ring_size = qinfo->len;

	cq->next_to_use = 0;
	cq->next_to_clean = 0;
	cq->next_to_post = cq->ring_size - 1;

	switch (qinfo->type) {
	case VIRTCHNL2_QUEUE_TYPE_RX:
		is_rxq = true;
		fallthrough;
	case VIRTCHNL2_QUEUE_TYPE_TX:
		err = libeth_ctlq_alloc_ring_res(hw, cq);
		break;
	default:
		err = -EBADR;
		break;
	}

	if (err)
		goto init_free_q;

	if (is_rxq) {
		libeth_ctlq_init_rxq_bufs(cq);
	} else {
		/* Allocate the array of msg pointers for TX queues */
		cq->bi.tx_msg = kcalloc(qinfo->len,
					sizeof(struct libeth_ctlq_msg *),
					GFP_KERNEL);
		if (!cq->bi.tx_msg) {
			err = -ENOMEM;
			goto init_dealloc_q_mem;
		}
	}

	libeth_ctlq_setup_regs(cq, qinfo);
	libeth_ctlq_init_regs(hw, cq, is_rxq);
	mutex_init(&cq->cq_lock);
	list_add(&cq->cq_list, &hw->cq_list_head);
	*cq_out = cq;

	return 0;

init_dealloc_q_mem:
	/* free ring buffers and the ring itself */
	libeth_ctlq_dealloc_ring_res(hw, cq);
init_free_q:
	kfree(cq);

	return err;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_add, LIBETH);

/**
 * libeth_ctlq_remove - deallocate and remove specified control queue
 * @hw: pointer to hardware struct
 * @cq: pointer to control queue to be removed
 */
void libeth_ctlq_remove(struct libeth_hw *hw,
		        struct libeth_ctlq_info *cq)
{
	list_del(&cq->cq_list);
	libeth_ctlq_shutdown(hw, cq);
	kfree(cq);
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_remove, LIBETH);

/**
 * libeth_ctlq_init - main initialization routine for all control queues
 * @hw: pointer to hardware struct
 * @num_q: number of queues to initialize
 * @q_info: array of structs containing info for each queue to be initialized
 *
 * This initializes any number and any type of control queues. This is an all
 * or nothing routine; if one fails, all previously allocated queues will be
 * destroyed. This must be called prior to using the individual add/remove
 * APIs.
 */
int libeth_ctlq_init(struct libeth_hw *hw, u8 num_q,
		     struct libeth_ctlq_create_info *q_info)
{
	struct libeth_ctlq_info *cq, *tmp;
	int err;
	int i;

	INIT_LIST_HEAD(&hw->cq_list_head);

	for (i = 0; i < num_q; i++) {
		struct libeth_ctlq_create_info *qinfo = q_info + i;

		err = libeth_ctlq_add(hw, qinfo, &cq);
		if (err)
			goto init_destroy_qs;
	}

	return 0;

init_destroy_qs:
	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		libeth_ctlq_remove(hw, cq);

	return err;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_init, LIBETH);

/**
 * libeth_ctlq_deinit - destroy all control queues
 * @hw: pointer to hw struct
 */
void libeth_ctlq_deinit(struct libeth_hw *hw)
{
	struct libeth_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		libeth_ctlq_remove(hw, cq);
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_deinit, LIBETH);

/**
 * libeth_ctlq_send - send command to Control Queue (CTQ)
 * @hw: pointer to hw struct
 * @cq: handle to control queue struct to send on
 * @num_q_msg: number of messages to send on control queue
 * @q_msg: pointer to array of queue messages to be sent
 *
 * The caller is expected to allocate DMAable buffers and pass them to the
 * send routine via the q_msg struct / control queue specific data struct.
 * The control queue will hold a reference to each send message until
 * the completion for that message has been cleaned.
 */
int libeth_ctlq_send(struct libeth_hw *hw, struct libeth_ctlq_info *cq,
		     u16 num_q_msg, struct libeth_ctlq_msg q_msg[])
{
	struct libeth_ctlq_desc *desc;
	int num_desc_avail;
	int err = 0;
	int i;

	mutex_lock(&cq->cq_lock);

	/* Ensure there are enough descriptors to send all messages */
	num_desc_avail = LIBETH_CTLQ_DESC_UNUSED(cq);
	if (num_desc_avail == 0 || num_desc_avail < num_q_msg) {
		err = -ENOSPC;
		goto err_unlock;
	}

	for (i = 0; i < num_q_msg; i++) {
		struct libeth_ctlq_msg *msg = &q_msg[i];

		desc = LIBETH_CTLQ_DESC(cq, cq->next_to_use);

		desc->opcode = cpu_to_le16(msg->opcode);
		desc->pfid_vfid = cpu_to_le16(msg->func_id);

		desc->v_opcode_dtype = cpu_to_le32(msg->cookie.mbx.chnl_opcode);
		desc->v_retval = cpu_to_le32(msg->cookie.mbx.chnl_retval);

		desc->flags = cpu_to_le16((msg->host_id & LIBETH_HOST_ID_MASK) <<
					  LIBETH_CTLQ_FLAG_HOST_ID_S);
		if (msg->data_len) {
			struct libeth_dma_mem *buff = msg->ctx.indirect.payload;

			desc->datalen |= cpu_to_le16(msg->data_len);
			desc->flags |= cpu_to_le16(LIBETH_CTLQ_FLAG_BUF);
			desc->flags |= cpu_to_le16(LIBETH_CTLQ_FLAG_RD);

			/* Update the address values in the desc with the pa
			 * value for respective buffer
			 */
			desc->params.indirect.addr_high =
				cpu_to_le32(upper_32_bits(buff->pa));
			desc->params.indirect.addr_low =
				cpu_to_le32(lower_32_bits(buff->pa));

			memcpy(&desc->params, msg->ctx.indirect.context,
			       LIBETH_INDIRECT_CTX_SIZE);
		} else {
			memcpy(&desc->params, msg->ctx.direct,
			       LIBETH_DIRECT_CTX_SIZE);
		}

		/* Store buffer info */
		cq->bi.tx_msg[cq->next_to_use] = msg;

		(cq->next_to_use)++;
		if (cq->next_to_use == cq->ring_size)
			cq->next_to_use = 0;
	}

	/* Force memory write to complete before letting hardware
	 * know that there are new descriptors to fetch.
	 */
	dma_wmb();

	wr32(hw, cq->reg.tail, cq->next_to_use);

err_unlock:
	mutex_unlock(&cq->cq_lock);

	return err;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_send, LIBETH);

/**
 * libeth_ctlq_clean_sq - reclaim send descriptors on HW write back for the
 * requested queue
 * @cq: pointer to the specific Control queue
 * @clean_count: (input|output) number of descriptors to clean as input, and
 * number of descriptors actually cleaned as output
 * @msg_status: (output) pointer to msg pointer array to be populated; needs
 * to be allocated by caller
 * @force: (input) clean descriptors which were not done yet. Use with caution
 * in kernel mode only
 *
 * Returns an array of message pointers associated with the cleaned
 * descriptors. The pointers are to the original ctlq_msgs sent on the cleaned
 * descriptors.  The status will be returned for each; any messages that failed
 * to send will have a non-zero status. The caller is expected to free original
 * ctlq_msgs and free or reuse the DMA buffers.
 */
int libeth_ctlq_clean_sq(struct libeth_ctlq_info *cq, u16 *clean_count,
			 struct libeth_ctlq_msg *msg_status[], bool force)
{
	struct libeth_ctlq_desc *desc;
	u16 i, num_to_clean;
	u16 ntc, desc_err;

	if (*clean_count == 0)
		return 0;
	if (*clean_count > cq->ring_size)
		return -EBADR;

	mutex_lock(&cq->cq_lock);

	ntc = cq->next_to_clean;

	num_to_clean = *clean_count;

	for (i = 0; i < num_to_clean; i++) {
		/* Fetch next descriptor and check if marked as done */
		desc = LIBETH_CTLQ_DESC(cq, ntc);
		if (!force && !LIBETH_DESC_MARKED_DONE(desc))
			break;

		/* strip off FW internal code */
		desc_err = le16_to_cpu(desc->ret_val) & 0xff;

		msg_status[i] = cq->bi.tx_msg[ntc];
		msg_status[i]->status = desc_err;

		cq->bi.tx_msg[ntc] = NULL;

		/* Zero out any stale data */
		memset(desc, 0, sizeof(*desc));

		ntc++;
		if (ntc == cq->ring_size)
			ntc = 0;
	}

	cq->next_to_clean = ntc;

	mutex_unlock(&cq->cq_lock);

	/* Return number of descriptors actually cleaned */
	*clean_count = i;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_clean_sq, LIBETH);

/**
 * libeth_ctlq_post_rx_buffs - post buffers to descriptor ring
 * @hw: pointer to hw struct
 * @cq: pointer to control queue handle
 * @buff_count: (input|output) input is number of buffers caller is trying to
 * return; output is number of buffers that were not posted
 * @buffs: array of pointers to dma mem structs to be given to hardware
 *
 * Caller uses this function to return DMA buffers to the descriptor ring after
 * consuming them; buff_count will be the number of buffers.
 *
 * Note: this function needs to be called after a receive call even
 * if there are no DMA buffers to be returned, i.e. buff_count = 0,
 * buffs = NULL to support direct commands
 */
int libeth_ctlq_post_rx_buffs(struct libeth_hw *hw, struct libeth_ctlq_info *cq,
			      u16 *buff_count, struct libeth_dma_mem **buffs)
{
	struct libeth_ctlq_desc *desc;
	u16 ntp = cq->next_to_post;
	bool buffs_avail = false;
	u16 tbp = ntp + 1;
	int i = 0;

	if (*buff_count > cq->ring_size)
		return -EBADR;

	if (*buff_count > 0)
		buffs_avail = true;

	mutex_lock(&cq->cq_lock);

	if (tbp >= cq->ring_size)
		tbp = 0;

	if (tbp == cq->next_to_clean)
		/* Nothing to do */
		goto post_buffs_out;

	/* Post buffers for as many as provided or up until the last one used */
	while (ntp != cq->next_to_clean) {
		desc = LIBETH_CTLQ_DESC(cq, ntp);

		if (cq->bi.rx_buff[ntp])
			goto fill_desc;
		if (!buffs_avail) {
			/* If the caller hasn't given us any buffers or
			 * there are none left, search the ring itself
			 * for an available buffer to move to this
			 * entry starting at the next entry in the ring
			 */
			tbp = ntp + 1;

			/* Wrap ring if necessary */
			if (tbp >= cq->ring_size)
				tbp = 0;

			while (tbp != cq->next_to_clean) {
				if (cq->bi.rx_buff[tbp]) {
					cq->bi.rx_buff[ntp] =
						cq->bi.rx_buff[tbp];
					cq->bi.rx_buff[tbp] = NULL;

					/* Found a buffer, no need to
					 * search anymore
					 */
					break;
				}

				/* Wrap ring if necessary */
				tbp++;
				if (tbp >= cq->ring_size)
					tbp = 0;
			}

			if (tbp == cq->next_to_clean)
				goto post_buffs_out;
		} else {
			/* Give back pointer to DMA buffer */
			cq->bi.rx_buff[ntp] = buffs[i];
			i++;

			if (i >= *buff_count)
				buffs_avail = false;
		}

fill_desc:
		desc->flags =
			cpu_to_le16(LIBETH_CTLQ_FLAG_BUF | LIBETH_CTLQ_FLAG_RD);

		/* Post buffers to descriptor */
		desc->datalen = cpu_to_le16(cq->bi.rx_buff[ntp]->size);
		desc->params.indirect.addr_high =
			cpu_to_le32(upper_32_bits(cq->bi.rx_buff[ntp]->pa));
		desc->params.indirect.addr_low =
			cpu_to_le32(lower_32_bits(cq->bi.rx_buff[ntp]->pa));

		ntp++;
		if (ntp == cq->ring_size)
			ntp = 0;
	}

post_buffs_out:
	/* Only update tail if buffers were actually posted */
	if (cq->next_to_post != ntp) {
		if (ntp)
			/* Update next_to_post to ntp - 1 since current ntp
			 * will not have a buffer
			 */
			cq->next_to_post = ntp - 1;
		else
			/* Wrap to end of end ring since current ntp is 0 */
			cq->next_to_post = cq->ring_size - 1;

		dma_wmb();

		wr32(hw, cq->reg.tail, cq->next_to_post);
	}

	mutex_unlock(&cq->cq_lock);

	/* return the number of buffers that were not posted */
	*buff_count = *buff_count - i;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_post_rx_buffs, LIBETH);

/**
 * libeth_ctlq_recv - receive control queue message call back
 * @cq: pointer to control queue handle to receive on
 * @num_q_msg: (input|output) input number of messages that should be received;
 * output number of messages actually received
 * @q_msg: (output) array of received control queue messages on this q;
 * needs to be pre-allocated by caller for as many messages as requested
 *
 * Called by interrupt handler or polling mechanism. Caller is expected
 * to free buffers
 */
int libeth_ctlq_recv(struct libeth_ctlq_info *cq, u16 *num_q_msg,
		     struct libeth_ctlq_msg *q_msg)
{
	struct libeth_ctlq_desc *desc;
	u16 num_to_clean, ntc, flags;
	int err = 0;
	u16 i;

	/* take the lock before we start messing with the ring */
	mutex_lock(&cq->cq_lock);

	ntc = cq->next_to_clean;

	num_to_clean = *num_q_msg;

	for (i = 0; i < num_to_clean; i++) {
		/* Fetch next descriptor and check if marked as done */
		desc = LIBETH_CTLQ_DESC(cq, ntc);
		flags = le16_to_cpu(desc->flags);

		if (!LIBETH_DESC_MARKED_DONE(desc))
			break;

		q_msg[i].vmvf_type = (flags &
				      (LIBETH_CTLQ_FLAG_FTYPE_VM |
				       LIBETH_CTLQ_FLAG_FTYPE_PF)) >>
				       LIBETH_CTLQ_FLAG_FTYPE_S;

		if (flags & LIBETH_CTLQ_FLAG_ERR)
			err  = -EBADMSG;

		q_msg[i].cookie.mbx.chnl_opcode =
				le32_to_cpu(desc->v_opcode_dtype);
		q_msg[i].cookie.mbx.chnl_retval =
				le32_to_cpu(desc->v_retval);

		q_msg[i].opcode = le16_to_cpu(desc->opcode);
		q_msg[i].data_len = le16_to_cpu(desc->datalen);
		q_msg[i].status = le16_to_cpu(desc->ret_val);

		if (desc->datalen) {
			memcpy(q_msg[i].ctx.indirect.context,
			       &desc->params.indirect, LIBETH_INDIRECT_CTX_SIZE);

			/* Assign pointer to dma buffer to ctlq_msg array
			 * to be given to upper layer
			 */
			q_msg[i].ctx.indirect.payload = cq->bi.rx_buff[ntc];

			/* Zero out pointer to DMA buffer info;
			 * will be repopulated by post buffers API
			 */
			cq->bi.rx_buff[ntc] = NULL;
		} else {
			memcpy(q_msg[i].ctx.direct, desc->params.raw,
			       LIBETH_DIRECT_CTX_SIZE);
		}

		/* Zero out stale data in descriptor */
		memset(desc, 0, sizeof(struct libeth_ctlq_desc));

		ntc++;
		if (ntc == cq->ring_size)
			ntc = 0;
	}

	cq->next_to_clean = ntc;

	mutex_unlock(&cq->cq_lock);

	*num_q_msg = i;
	if (*num_q_msg == 0)
		err = -ENOMSG;

	return err;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_recv, LIBETH);

/**
 * libeth_ctlq_xn_pop_free - get a free xn entry from the free list
 * @xnm: pointer to transaction manager
 *
 * Retrieve a free xn entry from the free list
 *
 */
static struct libeth_ctlq_xn *
libeth_ctlq_xn_pop_free(struct libeth_ctlq_xn_manager *xnm)
{
	struct libeth_ctlq_xn *xn;
	unsigned long free_idx;

	spin_lock_bh(&xnm->free_xns_bm_lock);

	free_idx = find_next_bit(xnm->free_xns_bm, LIBETH_CTLQ_MAX_XN_ENTRIES,
				 0);
	if (free_idx == LIBETH_CTLQ_MAX_XN_ENTRIES)
		goto do_unlock;

	clear_bit(free_idx, xnm->free_xns_bm);
	xn = &xnm->ring[free_idx];
	xn->cookie = xnm->cookie++;

do_unlock:	
	spin_unlock_bh(&xnm->free_xns_bm_lock);

	return xn;
}

/**
 * libeth_ctlq_xn_push_free - push a xn entry into free list
 * @xnm: pointer to transaction manager
 * @xn: pointer to xn entry
 *
 * Add the used xn entry back to the free list
 *
 */
static void libeth_ctlq_xn_push_free(struct libeth_ctlq_xn_manager *xnm,
				     struct libeth_ctlq_xn *xn)
{
	if (xn->state == LIBETH_CTLQ_XN_SHUTDOWN)
		return;

	xn->recv_buf.iov_base = NULL;
	xn->recv_buf.iov_len = 0;
	xn->data_len = 0;
	xn->state = LIBETH_CTLQ_XN_IDLE;
	set_bit(xn->index, xnm->free_xns_bm);
}

/**
 * libeth_ctlq_xn_deinit_dma - Free the dma memory that allocated for
 * send messages
 * @hw: pointer to hw structure
 * @xnm: pointer to transaction manager
 *
 * Free the dma memory that allocated for send messages
 *
 */
static void libeth_ctlq_xn_deinit_dma(struct libeth_hw *hw,
				      struct libeth_ctlq_xn_manager *xnm)
{
	int i;

	for (i = 0; i < LIBETH_CTLQ_MAX_XN_ENTRIES; i++) {
		struct libeth_ctlq_xn *xn = &xnm->ring[i];

		if (xn->dma_mem) {
			libeth_free_dma_mem(hw, xn->dma_mem);
			kfree(xn->dma_mem);
		}
	}

	return;
}

/**
 * libeth_ctlq_xn_init_dma - pre allocate dma memory for send messages in xn
 * @hw: pointer to hw structure
 * @xnm: pointer to transaction manager
 *
 * pre allocate dma memory for send messages in xn
 *
 */
static int libeth_ctlq_xn_init_dma(struct libeth_hw *hw,
				   struct libeth_ctlq_xn_manager *xnm)
{
	struct libeth_dma_mem *dma_mem;
	int i;

	for (i = 0; i < LIBETH_CTLQ_MAX_XN_ENTRIES; i++) {
		struct libeth_ctlq_xn *xn = &xnm->ring[i];

		dma_mem = kcalloc(1, sizeof(*dma_mem), GFP_KERNEL);
		if (!dma_mem)
			break;
		dma_mem->va = libeth_alloc_dma_mem(hw, dma_mem,
						   LIBETH_CTLQ_MAX_BUF_LEN);
		if (!dma_mem->va) {
			kfree(dma_mem);
			break;
		}
		xn->dma_mem = dma_mem;
	}

	/* dma allocate failed, so free the allocated ones and fail the init */
	if (i < LIBETH_CTLQ_MAX_XN_ENTRIES) {
		libeth_ctlq_xn_deinit_dma(hw, xnm);
		return -ENOMEM;
	}
	return 0;
}

/**
 * libeth_ctlq_xn_process_recv - process a control queue receive message
 * @params: pointer to receive param structure
 * @ctlq_msg: pointer to control queue message
 *
 * Process a control queue receive message and send a complete event
 * notification
 *
 */
static int libeth_ctlq_xn_process_recv(struct libeth_ctlq_xn_recv_params *params,
				       struct libeth_ctlq_msg *ctlq_msg)
{
	async_ctlq_resp_cb async_resp_cb = NULL;
	size_t payload_size, return_size;
	struct libeth_ctlq_xn *xn;
	struct kvec recv_buf;
	u16 msg_cookie;
	void *payload;
	u8 xn_index;
	int status;
	void *ctx;
	int ret;

	xn_index = FIELD_GET(LIBETH_CTLQ_XN_INDEX_M,
			     ctlq_msg->ctx.sw_cookie.data);
	msg_cookie = FIELD_GET(LIBETH_CTLQ_XN_COOKIE_M,
			       ctlq_msg->ctx.sw_cookie.data);
	payload = ctlq_msg->ctx.indirect.payload->va;
	payload_size = ctlq_msg->data_len;
	status = (ctlq_msg->cookie.mbx.chnl_retval) ? -EBADMSG : 0;

	if (xn_index >= LIBETH_CTLQ_MAX_XN_ENTRIES) {
		return -ENXIO;
	}
	xn = &params->xnm->ring[xn_index];

	if (xn->cookie != msg_cookie ||
	    ctlq_msg->cookie.mbx.chnl_opcode != xn->virtchnl_opcode) {
		return -ENXIO;
	}

	spin_lock_bh(&xn->lock);
	if ((xn->state != LIBETH_CTLQ_XN_ASYNC) &&
	    (xn->state != LIBETH_CTLQ_XN_WAITING)) {
		ret = -EBADMSG;
		goto exit;
	}

	return_size = (xn->recv_buf.iov_len < payload_size) ?
		       xn->recv_buf.iov_len : payload_size;
	if (xn->recv_buf.iov_base && return_size) {
		memcpy(xn->recv_buf.iov_base, payload, return_size);
		xn->data_len = return_size;
	}

	if (xn->state == LIBETH_CTLQ_XN_ASYNC) {
		async_resp_cb = xn->async_resp_cb;
		ctx = xn->ctx;
		recv_buf = xn->recv_buf;
		ret = 0;
		goto exit;
	}

	xn->state = status ? LIBETH_CTLQ_XN_COMPLETED_FAILED :
			     LIBETH_CTLQ_XN_COMPLETED_SUCCESS;
	spin_unlock_bh(&xn->lock);
	complete(&xn->cmd_completion_event);
	return 0;

exit:
	libeth_ctlq_xn_push_free(params->xnm, xn);
	spin_unlock_bh(&xn->lock);

	/* call the callback after xn unlock */
	if (async_resp_cb)
		async_resp_cb(ctx, recv_buf.iov_base, return_size, status);
	return ret;
}

/**
 * libeth_ctlq_xn_recv - Function to handle a receive message
 * @params: pointer to receive param structure
 *
 * Process a receive message and update the receive queue buffer
 *
 */
int libeth_ctlq_xn_recv(struct libeth_ctlq_xn_recv_params *params)
{
	struct libeth_dma_mem *dma_mem = NULL;
	struct libeth_ctlq_msg ctlq_msg;
	u16 num_recv = 1;
	int ret;

	if (!params || !params->hw || !params->xnm ||
	    !params->ctlq_info || !params->default_msg_handler)
		return -EBADR;

	ret = libeth_ctlq_recv(params->ctlq_info, &num_recv, &ctlq_msg);
	if (ret)
		return ret;

	if (ctlq_msg.data_len)
		dma_mem = ctlq_msg.ctx.indirect.payload;

	ret = libeth_ctlq_xn_process_recv(params, &ctlq_msg);
	/* Call the default handler for HMA event messages */
	if (ret == -ENXIO)
		ret = params->default_msg_handler(params->hw, &ctlq_msg);
	ret = libeth_ctlq_post_rx_buffs(params->hw, params->ctlq_info,
					&num_recv, &dma_mem);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_xn_recv, LIBETH);

/**
 * libeth_ctlq_xn_process_send - process and send a control queue message
 * @params: pointer to send params structure
 * @xn: pointer to xn entry
 *
 * Process and send a control queue message
 *
 */
static
int libeth_ctlq_xn_process_send(struct libeth_ctlq_xn_send_params *params,
				struct libeth_ctlq_xn *xn)
{
	u16 cookie;
	int ret;

	/* It's possible we're just sending an opcode but no buffer */
	if (params->send_buf.iov_base && params->send_buf.iov_len) {
		if (params->send_buf.iov_len >= LIBETH_CTLQ_MAX_BUF_LEN)
			return -EBADMSG;

		memcpy(xn->dma_mem->va, params->send_buf.iov_base,
		       params->send_buf.iov_len);
		params->ctlq_msg->ctx.indirect.payload = xn->dma_mem;
	}
	cookie = FIELD_PREP(LIBETH_CTLQ_XN_COOKIE_M, xn->cookie) |
		 FIELD_PREP(LIBETH_CTLQ_XN_INDEX_M, xn->index);
	params->ctlq_msg->ctx.sw_cookie.data = cookie;
	ret = libeth_ctlq_send(params->hw, params->ctlq_info, 1,
			       params->ctlq_msg);

	return ret;
}

/**
 * libeth_ctlq_xn_send - Function to send a control queue message
 * @params: pointer to send param structure
 *
 * Send a control queue (mailbox or config) message.
 * Based on the params value, the call can be completed synchronusly or
 * asynchronusly.
 *
 */
int libeth_ctlq_xn_send(struct libeth_ctlq_xn_send_params *params)
{
	struct libeth_ctlq_xn *xn;
	int ret;

	if (!params || !params->hw || !params->xnm ||
	    !params->ctlq_msg || !params->ctlq_info)
		return -EBADR;

	xn = libeth_ctlq_xn_pop_free(params->xnm);
	/* no free transactions available */
	if (!xn)
		return -EBUSY;

	spin_lock_bh(&xn->lock);
	if (xn->state == LIBETH_CTLQ_XN_SHUTDOWN) {
		ret = -ENXIO;
		goto error;
	} else if (xn->state != LIBETH_CTLQ_XN_IDLE) {
		/* We're just going to clobber this transaction even though
		 * it's not IDLE. If we don't reuse it we could theoretically
		 * eventually leak all the free transactions and not be able to
		 * send any messages. At least this way we make an attempt to
		 * remain functional even though something really bad is
		 * happening that's corrupting what was supposed to be free
		 * transactions.
		 */
		WARN_ONCE(1, "There should only be idle transactions in free list (idx %d)\n", xn->index);
		ret = -EBUSY;
		goto error;
	}
	xn->recv_buf = params->recv_buf;
	xn->state = params->async_resp_cb ? LIBETH_CTLQ_XN_ASYNC :
					    LIBETH_CTLQ_XN_WAITING;
	xn->send_ctlq_info = params->ctlq_info;
	xn->virtchnl_opcode = params->ctlq_msg->cookie.mbx.chnl_opcode;
	/* if callback is not provided then process it as a synchronous
	   message */
	if (!params->async_resp_cb)
		reinit_completion(&xn->cmd_completion_event);
	else {
		xn->ctx = params->ctx;
		xn->async_resp_cb = params->async_resp_cb;
	}
	spin_unlock_bh(&xn->lock);

	ret = libeth_ctlq_xn_process_send(params, xn);
	if (ret)
		goto error;

	if (params->async_resp_cb)
		return 0;
	/* wait for the command completion */
	wait_for_completion_timeout(&xn->cmd_completion_event,
				    params->timeout_ms);

	spin_lock_bh(&xn->lock);
	switch (xn->state) {
	case LIBETH_CTLQ_XN_WAITING:
		ret = -ETIME;
		break;
	case LIBETH_CTLQ_XN_COMPLETED_SUCCESS:
		params->data_len = xn->data_len;
		ret = 0;
		break;
	default:
		ret = -EBADMSG;
		break;
	}
	libeth_ctlq_xn_push_free(params->xnm, xn);

error:
	spin_unlock_bh(&xn->lock);
	return ret;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_xn_send, LIBETH);

/**
 * libeth_ctlq_xn_send_clean - cleanup the send control queue message buffers
 * @params: pointer to params struct
 *
 * Cleanup the send buffers for the given control queue, if force is set, then
 * clear all the outstanding send messages irrrespective their send status.
 * Force should be used during deinit or reset.
 *
 */
int libeth_ctlq_xn_send_clean(struct libeth_ctlq_xn_clean_params *params)
{
	int ret = 0;

	if (!params || !params->hw || !params->ctlq_info ||
	    !params->num_msgs || !params->q_msg)
		return -EBADR;

	ret = libeth_ctlq_clean_sq(params->ctlq_info, &params->num_msgs,
				   params->q_msg, params->force);

	return ret;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_xn_send_clean, LIBETH);

/**
 * libeth_ctlq_xn_deinit - deallocate and free the transaction manager resources
 * @params: pointer to xn init params
 *
 * Deallocate and free the transaction manager structure.
 *
 */
int libeth_ctlq_xn_deinit(struct libeth_ctlq_xn_init_params *params)
{
	enum libeth_ctlq_xn_state prev_state;
	int i;

	if (!params || !params->hw || !params->xnm)
		return -EBADR;

	for (i = 0; i < LIBETH_CTLQ_MAX_XN_ENTRIES; i++) {
		struct libeth_ctlq_xn *xn = &params->xnm->ring[i];

		spin_lock_bh(&xn->lock);
		prev_state = xn->state;
		xn->state = LIBETH_CTLQ_XN_SHUTDOWN;
		switch (prev_state) {
		case LIBETH_CTLQ_XN_WAITING:
			complete(&xn->cmd_completion_event);
			break;
		case LIBETH_CTLQ_XN_ASYNC:
			xn->async_resp_cb(params->hw, xn->recv_buf.iov_base, 0,
					  -EBADMSG);
			break;
		default:
			break;
		}
		spin_unlock_bh(&xn->lock);
	}

	spin_lock_bh(&params->xnm->free_xns_bm_lock);
	bitmap_clear(params->xnm->free_xns_bm, 0, LIBETH_CTLQ_MAX_XN_ENTRIES);
	spin_unlock_bh(&params->xnm->free_xns_bm_lock);
	libeth_ctlq_xn_deinit_dma(params->hw, params->xnm);

	kfree(params->xnm);
	libeth_ctlq_deinit(params->hw);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_xn_deinit, LIBETH);

/**
 * libeth_ctlq_xn_init - initialize transaction manager
 * @params: pointer to xn init params
 *
 * Allocate and initialize transaction manager structure.
 * Return success if no errors occur.
 *
 */
int libeth_ctlq_xn_init(struct libeth_ctlq_xn_init_params *params)
{
	struct libeth_ctlq_xn_manager *xnm;
	int i, ret;

	if (!params || !params->hw || !params->cctlq_info ||
	    !params->num_qs)
		return -EBADR;

	ret = libeth_ctlq_init(params->hw, params->num_qs, params->cctlq_info);
	if (ret)
		return ret;

	xnm = kcalloc(1, sizeof(struct libeth_ctlq_xn_manager), GFP_KERNEL);
	if (!xnm) {
		libeth_ctlq_deinit(params->hw);
		return -ENOMEM;
	}

	ret = libeth_ctlq_xn_init_dma(params->hw, xnm);
	if (ret) {
		kfree(xnm);
		libeth_ctlq_deinit(params->hw);
		return -ENOMEM;
	}

	spin_lock_init(&xnm->free_xns_bm_lock);
	bitmap_fill(xnm->free_xns_bm, LIBETH_CTLQ_MAX_XN_ENTRIES);

	for (i = 0; i < LIBETH_CTLQ_MAX_XN_ENTRIES; i++) {
		struct libeth_ctlq_xn *xn = &xnm->ring[i];

		xn->state = LIBETH_CTLQ_XN_IDLE;
		xn->index = i;
		init_completion(&xn->cmd_completion_event);
		spin_lock_init(&xn->lock);
	}

	params->xnm = xnm;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_ctlq_xn_init, LIBETH);
