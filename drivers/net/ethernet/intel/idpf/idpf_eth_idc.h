/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_ETH_IDC_H_
#define _IDPF_ETH_IDC_H_

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
 * struct idpf_eth_shared - Common Device data struct shared with eth
 * @msg_enable: Debug message level enabled
 */
struct idpf_eth_shared {
	u32 msg_enable;
};

int idpf_intr_init_vec_idx(struct idpf_adapter *adapter,
			   u16 num_vecs, struct idpf_q_vector *q_vectors,
			   u16 *q_vector_idxs);
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter,
				u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info);

#endif /* !_IDPF_ETH_IDC_H_ */
