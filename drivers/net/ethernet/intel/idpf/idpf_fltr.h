/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_FLTR_H_
#define _IDPF_FLTR_H_

#define IDPF_NUM_FILTERS_PER_MSG	20

/**
 * struct idpf_mac_filter
 * @list: list member field
 * @macaddr: MAC address
 * @remove: filter should be removed (virtchnl)
 * @add: filter should be added (virtchnl)
 */
struct idpf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	bool remove;
	bool add;
};

int idpf_init_mac_addr(struct idpf_vport *vport,
		       struct net_device *netdev);
void idpf_remove_mac_filters(struct idpf_vport *vport);
int idpf_add_mac_filter(struct idpf_vport *vport,
			struct idpf_netdev_priv *np,
			const u8 *macaddr, bool async);
void idpf_deinit_mac_addr(struct idpf_vport *vport);
void idpf_del_all_mac_filters(struct idpf_vport *vport);
void idpf_restore_mac_filters(struct idpf_vport *vport);
int __idpf_del_mac_filter(struct idpf_vport_config *vport_config,
			  const u8 *macaddr);
int idpf_del_mac_filter(struct idpf_vport *vport,
			struct idpf_netdev_priv *np,
			const u8 *macaddr, bool async);
int idpf_add_del_mac_filters(struct idpf_vport *vport,
			     struct idpf_netdev_priv *np,
			     bool add, bool async);
int idpf_set_promiscuous(struct idpf_adapter *adapter,
			 struct idpf_vport_user_config_data *config_data,
			 u32 vport_id);

#endif /* !_IDPF_FLTR_H_ */
