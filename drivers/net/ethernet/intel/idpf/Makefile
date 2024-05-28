# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2023 Intel Corporation

# Makefile for Intel(R) Infrastructure Data Path Function Linux Driver

subdir-ccflags-y += -I$(src)

obj-$(CONFIG_IDPF) += idpf.o

idpf-y := \
	idpf_controlq.o		\
	idpf_controlq_setup.o	\
	idpf_dev.o		\
	idpf_eth_idc.o		\
	idpf_lib.o		\
	idpf_main.o		\
	idpf_vf_dev.o		\
	idpf_virtchnl.o

idpf-y += \
	eth/idpf_eth.o		\
	eth/idpf_ethtool.o	\
	eth/idpf_fltr.o		\
	eth/idpf_netdev.o	\
	eth/idpf_singleq_txrx.o	\
	eth/idpf_txrx.o		\
	eth/idpf_vport.o	\
	eth/idpf_vport_config.o	\
	eth/idpf_vport_q.o	\
