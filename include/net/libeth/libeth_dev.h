/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _LIBETH_DEV_H_
#define _LIBETH_DEV_H_

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "libeth_controlq.h"
#include "libeth_virtchnl.h"
#include "libeth_eth_idc.h"

#define BAR0 0

#define LIBETH_NUM_DFLT_MBX_Q 2
#define LIBETH_DFLT_MBX_ID -1
#define LIBETH_DFLT_MBX_Q_LEN 64
#define LIBETH_CTLQ_MAX_BUF_LEN 4096

/**
 * struct libeth_reset_reg - structure for reset registers
 * @rstat: mmio address of status register
 * @rstat_m: status mask
 * @rtrigger: mmio address of reset trigger
 * @rtrigger_m: reset mask
 */
struct libeth_reset_reg {
	void __iomem *  rstat;
	u32   rstat_m;
	void __iomem *  rtrigger;
	u32   rtrigger_m;
};

/**
 * enum libeth_dev_state - device states in libeth
 */
enum libeth_dev_state {
	__LIBETH_VER_CHECK,
	__LIBETH_GET_CAPS,
	__LIBETH_INIT_SW,
	__LIBETH_STATE_LAST,
};

/**
 * struct idpf_vport - Handle for netdevices and queue resources
 * @vport_type: Default SRIOV, SIOV, etc.
 * @vport_id: Device given vport identifier
 * @max_mtu: device given max possible MTU
 * @default_mac_addr: device will give a default MAC to use
 */
struct libeth_vport {
	u16 vport_type;
	u32 vport_id;
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];

	u16 max_txq;
	u16 max_rxq;
	struct net_device *netdev;
	netdev_features_t dflt_features;
	netdev_features_t offloads;
};

/* virtchnl messsage apis */
int libeth_get_caps(struct libeth_hw *hw,
		    struct libeth_ctlq_info *ctlq_info,
		    struct libeth_ctlq_xn_manager *xnm,
		    struct virtchnl2_get_capabilities *caps);
int libeth_get_version(struct libeth_hw *hw,
		       struct libeth_ctlq_info *ctlq_info,
		       struct libeth_ctlq_xn_manager *xnm,
		       struct virtchnl2_version_info *version);
void libeth_trigger_reset(struct libeth_hw *hw,
		       struct libeth_ctlq_info *ctlq_info,
		       struct libeth_ctlq_xn_manager *xnm);
int libeth_create_vport(struct libeth_hw *hw,
			struct libeth_ctlq_info *ctlq_info,
			struct libeth_ctlq_xn_manager *xnm,
			struct virtchnl2_create_vport *cv,
			struct libeth_vport **vport);
int libeth_remove_vport(struct libeth_hw *hw,
			struct libeth_ctlq_info *ctlq_info,
			struct libeth_ctlq_xn_manager *xnm,
			struct libeth_vport **vport);

/* mailbox and device initialization apis */
int libeth_dev_state_init(struct libeth_hw *hw,
			  struct libeth_ctlq_info *ctlq_info,
			  struct libeth_ctlq_xn_manager *xnm,
			  struct virtchnl2_version_info *version,
			  struct virtchnl2_get_capabilities *caps,
			  enum libeth_dev_state *state);
struct libeth_ctlq_info *
libeth_find_ctlq(struct libeth_hw *hw, enum virtchnl2_queue_type type, int id);
int libeth_init_dflt_mbx(struct libeth_hw *hw, 
			 struct libeth_ctlq_xn_manager **xnm,
			 struct libeth_ctlq_reg *ctlq_reg_tx,
			 struct libeth_ctlq_reg *ctlq_reg_rx);
int libeth_deinit_dflt_mbx(struct libeth_hw *hw,
			   struct libeth_ctlq_xn_manager *xnm);
bool libeth_is_reset_detected(struct libeth_hw *hw,
			      struct libeth_ctlq_info *ctlq_info);
int libeth_check_reset_complete(struct libeth_hw *hw,
				struct libeth_reset_reg *reset_reg);
void libeth_pf_trigger_reset(struct libeth_hw *hw,
			     struct libeth_reset_reg *reset_reg);
int libeth_setup_device(struct pci_dev *pdev);

void libeth_idc_eth_dev_event_handler(struct idc_eth_auxiliary_dev *eth_dev,
				      enum idc_eth_event_type event_type);
int libeth_idc_eth_dev_vc_receive(struct idc_eth_auxiliary_dev *eth_dev,
				  u16 virt_opcode, u8 *msg, u16 msg_size);
struct idc_eth_auxiliary_dev * 
libeth_idc_eth_dev_create(struct pci_dev *pdev,
			  struct virtchnl2_get_capabilities *caps,
			  struct idc_eth_extended_caps_info *ext_caps,
			  struct libeth_mmio_region *mem_regions,
			  int num_regions, struct idc_eth_ops *ops);
void libeth_idc_eth_dev_destroy(struct idc_eth_auxiliary_dev **eth_dev);

int libeth_cfg_netdev(struct libeth_vport *vport,
		      struct net_device_ops *dev_ops,
		      struct ethtool_ops *ethtool_ops, int private_data_size);
void libeth_decfg_netdev(struct libeth_vport *vport);

#endif /* _LIBETH_DEV_H_ */
