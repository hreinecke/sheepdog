/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * configdb.h
 * SQLite3 configfs emulation header file
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#ifndef _CONFIGDB_H
#define _CONFIGDB_H

int configdb_open(const char *filename);
void configdb_close(const char *filename);

int configdb_count_table(const char *tbl, int *num);

int configdb_add_host(const char *nqn);
int configdb_del_host(const char *nqn);

int configdb_add_subsys(const char *nqn, uint32_t id, int type);
int configdb_get_discovery_nqn(char *nqn);
int configdb_set_discovery_nqn(const char *nqn);
int configdb_get_subsys_attr(const char *nqn, const char *attr, char *buf);
int configdb_set_subsys_attr(const char *nqn, const char *attr, const char *buf);
int configdb_del_subsys(uint32_t id);

int configdb_add_namespace(uint32_t subsys_id, uint32_t nsid,
			   uuid_t uuid, uint32_t agid);
int configdb_count_namespaces(const char *subsysnqn, int *num);
int configdb_get_namespace_attr(uint32_t subsys_id, uint32_t nsid,
				const char *attr, char *buf);
int configdb_set_namespace_attr(uint32_t subsys_id, uint32_t nsid,
				const char *attr, const char *buf);
int configdb_get_namespace_anagrp(const char *subsysnqn, uint32_t nsid,
			       int *ana_grpid);
int configdb_set_namespace_anagrp(const char *subsysnqn, uint32_t nsid,
			       int ana_grpid);
int configdb_del_namespace(uint32_t subsys_id, uint32_t nsid);

int configdb_add_ana_group(unsigned int grpid);
int configdb_del_ana_group(unsigned int grpid);

int configdb_add_ana_port_group(unsigned int portid);
int configdb_get_ana_port_group(unsigned int portid, const char *ana_grpid,
				int *ana_state);
int configdb_set_ana_port_group(unsigned int portid, const char *ana_grpid,
				int ana_state);
int configdb_del_ana_port_group(unsigned int portid, int grpid);

int configdb_add_host_subsys(const char *hostnqn, const char *subsysnqn);
int configdb_count_host_subsys(const char *subsysnqn, int *num_hosts);
int configdb_del_host_subsys(const char *hostnqn, const char *subsysnqn);

int configdb_add_ctrl(const char *subsysnqn, int cntlid);
int configdb_get_cntlid(const char *subsysnqn, uint16_t *cntlid);
int configdb_del_ctrl(const char *subsysnqn, int cntlid);

int configdb_add_port(unsigned int port, const char *traddr,
		      const char *adrfam, unsigned int trsvcid);
int configdb_get_port_attr(unsigned int port, const char *attr, char *buf);
int configdb_set_port_attr(unsigned int port, const char *attr, const char *buf);
int configdb_del_port(unsigned int port);

int configdb_add_subsys_port(const char *subsysnqn, unsigned int port);
int configdb_count_subsys_port(unsigned int port, int *num_ports);
int configdb_del_subsys_port(const char *subsysnqn, unsigned int port);

int configdb_check_allowed_host(const char *hostnqn, const char *subsysnqn,
			     unsigned int portid);
int configdb_host_disc_entries(const char *hostnqn, uint8_t *log, int log_len);
int configdb_host_genctr(const char *hostnqn, int *genctr);
int configdb_subsys_identify_ctrl(const char *subsysnqn,
				  struct nvme_id_ctrl *id);
int configdb_identify_active_ns(const char *subsysnqn,
				uint8_t *ns_list, size_t len);
int configdb_ana_log_entries(const char *subsysnqn, unsigned int portid,
			     uint8_t *log, int log_len);
int configdb_ns_changed_log_entries(const char *subsysnqn, uint16_t cntlid,
				    uint8_t *log, int log_len);

#endif /* _CONFIGDB_H */


