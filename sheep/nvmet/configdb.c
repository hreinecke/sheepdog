/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * configdb.c
 * SQLite3 configfs emulation
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>

#include "sheep.h"
#include "nofuse.h"
#include "configdb.h"
#include "firmware.h"

static sqlite3 *configdb_db;

#define COMMIT_TRANSACTION \
	_ret = sql_exec_simple("COMMIT TRANSACTION;");	\
	if (_ret) {					\
		sd_err("%s: commit failed, "		\
		       "database inconsistent.", __func__);	\
		return _ret;					\
	}

#define ROLLBACK_TRANSACTION \
	_ret = sql_exec_simple("ROLLBACK TRANSACTION;");	\
	if (_ret) {						\
		sd_err("%s: rollback failed, "			\
		       "database inconsistent.", __func__);	\
		return _ret;					\
	}

static int sql_exec_error(int ret, const char *sql, char *errmsg)
{
	if (ret != SQLITE_OK) {
		sd_err("SQL error executing %s", sql);
		sd_err("SQL error: %s", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

static int sql_simple_cb(void *unused, int argc, char **argv, char **colname)
{
	int i, off = 0;
	char *line;

	line = malloc(1024);
	for (i = 0; i < argc; i++) {
		off += sprintf(line + off, "%s ", colname[i]);
	}
	sd_debug("%s", line);
	off = 0;
	for (i = 0; i < argc; i++) {
		off += sprintf(line + off, "%s ",
			       argv[i] ? argv[i] : "NULL");
	}
	sd_debug("%s", line);
	free(line);
	return 0;
}

static int sql_exec_simple(const char *sql)
{
	int ret;
	char *errmsg = NULL;

	ret = sqlite3_exec(configdb_db, sql, sql_simple_cb, NULL, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	return ret;
}

struct sql_int_value_parm {
	const char *col;
	int val;
	int done;
};

static int sql_int_value_cb(void *argp, int argc, char **argv, char **colname)
{
	struct sql_int_value_parm *parm = argp;
	int i;

	if (parm->done != 0) {
		parm->done = -ENOTUNIQ;
		return 0;
	}

	for (i = 0; i < argc; i++) {
		char *eptr = NULL;

		if (strcmp(parm->col, colname[i])) {
			sd_warn("%s: ignore col %s", __func__,
				colname[i]);
			continue;
		}
		if (!argv[i]) {
			parm->val = 0;
			parm->done = 1;
			break;
		}
		parm->val = strtol(argv[i], &eptr, 10);
		if (argv[i] == eptr) {
			parm->done = -EDOM;
			break;
		}
		parm->done = 1;
	}
	return 0;
}

static int sql_exec_int(const char *sql, const char *col, int *value)
{
	char *errmsg;
	struct sql_int_value_parm parm = {
		.col = col,
		.val = 0,
		.done = 0,
	};
	int ret;

	ret = sqlite3_exec(configdb_db, sql, sql_int_value_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret < 0) {
		parm.done = -ret;
	}
	if (parm.done < 0)
		sd_err("value error for '%s': %s", col,
		       strerror(-parm.done));
	else if (parm.done > 0) {
		if (value)
			*value = parm.val;
		parm.done = 0;
	} else {
		*value = 0;
		parm.done = -ENOENT;
	}
	return parm.done;
}

struct sql_str_value_parm {
	const char *col;
	char *val;
	int done;
};

static int sql_str_value_cb(void *argp, int argc, char **argv, char **colname)
{
	struct sql_str_value_parm *parm = argp;
	int i;

	if (parm->done != 0) {
		parm->done = -ENOTUNIQ;
		return 0;
	}

	for (i = 0; i < argc; i++) {
		if (strcmp(parm->col, colname[i])) {
			sd_warn("%s: ignore col %s", __func__,
				colname[i]);
			continue;
		}
		if (parm->val) {
			if (!argv[i])
				*parm->val = '\0';
			else
				strcpy(parm->val, argv[i]);
		}
		parm->done = 1;
	}
	return 0;
}

static int sql_exec_str(const char *sql, const char *col, char *value)
{
	char *errmsg;
	struct sql_str_value_parm parm = {
		.col = col,
		.val = value,
		.done = 0,
	};
	int ret;

	ret = sqlite3_exec(configdb_db, sql, sql_str_value_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret < 0) {
		parm.done = ret;
	}
	if (parm.done < 0)
		sd_err("value error for '%s': %s", col,
		       strerror(-parm.done));
	else if (parm.done > 0)
		parm.done = 0;
	else
		parm.done = -ENOENT;
	return parm.done;
}

#define NUM_TABLES 20

static const char *init_sql[NUM_TABLES] = {
	/* hosts */
	"CREATE TABLE hosts ( "
	"nqn VARCHAR(223) UNIQUE NOT NULL, genctr INTEGER DEFAULT 0, "
	"ctime TIME );",
	/* subsystems */
	"CREATE TABLE subsystems ( "
	"nqn VARCHAR(223) UNIQUE NOT NULL, attr_allow_any_host INT DEFAULT 1, "
	"attr_firmware VARCHAR(256), attr_ieee_oui VARCHAR(256), "
	"attr_model VARCHAR(256), attr_serial VARCHAR(256), "
	"attr_version VARCHAR(256), attr_type INT DEFAULT 3, "
	"attr_qid_max INT, attr_vid INT UNIQUE NOT NULL, "
	"attr_cntlid_min INT DEFAULT 1, attr_cntlid_max INT DEFAULT 65519, "
	"cntlid_next INT DEFAULT 1, ctime TIME, "
	"ana_chgcnt INT DEFAULT 0, "
	"CHECK (attr_allow_any_host = 0 OR attr_allow_any_host = 1) );",
	/* ana_groups */
	"CREATE TABLE ana_groups ( id INTEGER PRIMARY KEY, "
	"CHECK (id > 0) );"
	/* controllers */
	"CREATE TABLE controllers ( "
	"cntlid INT NOT NULL, subsys_id INT, ctrl_type INT, "
	"CHECK (cntlid > 0 AND cntlid < 65534), "
	"UNIQUE(cntlid, subsys_id), "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* cntlid index */
	"CREATE UNIQUE INDEX cntlid_idx ON "
	"controllers(cntlid, subsys_id);",
	/* cntlid trigger */
	"CREATE TRIGGER cntlid_incr INSERT ON controllers "
	"BEGIN UPDATE subsystems SET cntlid_next = cntlid_next + 1 "
	"WHERE NEW.subsys_id = oid; END;",
	/* changed namespaces */
	"CREATE TABLE ns_changed ( ctrl_id INT, nsid INT, "
	"FOREIGN KEY (ctrl_id) REFERENCES controllers(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* namespaces */
	"CREATE TABLE namespaces ( "
	"device_eui64 VARCHAR(256), device_nguid VARCHAR(256), "
	"device_uuid VARCHAR(256) UNIQUE NOT NULL, "
	"device_size INT, device_blksize INT, device_enable INT DEFAULT 0, "
	"device_readonly INT DEFAULT 0,ana_group_id INT, "
	"nsid INTEGER NOT NULL, subsys_id INTEGER, ctime TIME, "
	"UNIQUE (subsys_id, nsid), "
	"CHECK (device_enable = 0 OR device_enable = 1), "
	"CHECK (device_readonly = 0 OR device_enable = 1), "
	"FOREIGN KEY (ana_group_id) REFERENCES ana_groups(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* nsid_idx */
	"CREATE UNIQUE INDEX nsid_idx ON "
	"namespaces(subsys_id, nsid); "
	/* subsys_ctrl view */
	"CREATE VIEW subsys_ctrl AS "
	"SELECT s.oid AS subsys_id, s.nqn AS subsys_nqn, "
	"c.oid AS ctrl_id, c.cntlid AS cntlid "
	"FROM controllers AS c "
	"INNER JOIN subsystems AS s ON c.subsys_id = s.oid;"
	/* subsys_ns_add trigger */
	"CREATE TRIGGER subsys_ns_add_trig INSERT ON namespaces "
	"BEGIN INSERT INTO ns_changed (ctrl_id, nsid) "
	"SELECT sc.ctrl_id, NEW.nsid FROM subsys_ctrl AS sc "
	"WHERE sc.subsys_id = NEW.subsys_id; END;",
	/* subsys_ns_del trigger */
	"CREATE TRIGGER subsys_ns_del_trig DELETE ON namespaces "
	"BEGIN INSERT INTO ns_changed (ctrl_id, nsid) "
	"SELECT sc.ctrl_id, OLD.nsid FROM subsys_ctrl AS sc "
	"WHERE sc.subsys_id = OLD.subsys_id; END;",
	/* ns_ana_port_group view */
	"CREATE VIEW ns_ana_port_group AS "
	"SELECT s.oid AS s_id, ns.nsid, ap.id AS ap_id "
	"FROM ana_port_group AS ap "
	"INNER JOIN namespaces AS n ON n.ana_group_id = ap.id "
	"INNER JOIN subsystems AS s ON s.oid = n.subsys_id;"
	/* ns_anagrp trigger */
	"CREATE TRIGGER ns_anagrp_update_trig UPDATE OF ana_group_id "
	"ON namespaces BEGIN UPDATE ana_port_group SET chgcnt = chgcnt + 1 "
	"FROM ns_ana_port_group AS napg "
	"WHERE napg.ap_id = NEW.ana_group_id AND "
	"napg.s_id = NEW.subsys_id AND napg.nsid = NEW.nsid; END;",
	/* ports */
	"CREATE TABLE ports ( id INTEGER PRIMARY KEY, "
	"addr_trtype CHAR(32) DEFAULT 'tcp', "
	"addr_adrfam CHAR(32) DEFAULT 'ipv4', "
	"addr_treq char(32) DEFAULT 'not specified', "
	"addr_bindaddr CHAR(255) DEFAULT '0.0.0.0', "
	"addr_traddr CHAR(255) DEFAULT '127.0.0.1', "
	"addr_trsvcid CHAR(32) DEFAULT '4420', "
	"addr_tsas CHAR(255) DEFAULT 'none', ctime TIME, "
	"UNIQUE(addr_trtype,addr_adrfam,addr_traddr,addr_trsvcid) );",
	/* port_addr_idx */
	"CREATE UNIQUE INDEX port_addr_idx ON "
	"ports(addr_trtype, addr_adrfam, addr_traddr, addr_trsvcid);",
	/* ana_port_group */
	"CREATE TABLE ana_port_group ( "
	"ana_group_id INT, ana_state INT DEFAULT '1', port_id INTEGER, "
	"chgcnt INT DEFAULT '0', ctime TIME, "
	"FOREIGN KEY (ana_group_id) REFERENCES ana_groups(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (port_id) REFERENCES ports(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* host_subsys */
	"CREATE TABLE host_subsys ( host_id INTEGER, subsys_id INTEGER, "
	"ctime TIME, "
	"FOREIGN KEY (host_id) REFERENCES hosts(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (subsys_id) REFERENCES subsys(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT);",
	/* host_subsys triger */
	"CREATE TRIGGER host_subsys_add_trig INSERT ON host_subsys "
	"BEGIN UPDATE hosts SET genctr = genctr + 1 "
	"WHERE oid = NEW.host_id; END;",
	/* subsys_port */
	"CREATE TABLE subsys_port ( subsys_id INTEGER, port_id INTEGER, "
	"ctime TIME, "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(oid) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (port_id) REFERENCES ports(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT);",
};

static const char *exit_sql[NUM_TABLES] =
{
	"DROP TABLE subsys_port;",
	"DROP TRIGGER host_subsys_add_trig;",
	"DROP TABLE host_subsys;",
	"DROP TABLE ana_port_group;",
	"DROP INDEX port_addr_idx;",
	"DROP TABLE ports;",
	"DROP TRIGGER ns_anagrp_update_trig;",
	"DROP VIEW ns_ana_port_group;",
	"DROP TRIGGER subsys_ns_del_trig;",
	"DROP TRIGGER subsys_ns_add_trig;",
	"DROP TABLE ns_changed;",
	"DROP VIEW subsys_ctrl;",
	"DROP INDEX nsid_idx;",
	"DROP TABLE namespaces;",
	"DROP TRIGGER cntlid_incr;",
	"DROP INDEX cntlid_idx;",
	"DROP TABLE controllers;",
	"DROP TABLE ana_groups;",
	"DROP TABLE subsystems;",
	"DROP TABLE hosts;",
};

static int configdb_init(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(init_sql[i]);
		if (ret)
			break;
	}

	if (ret) {
		while (i >= 0) {
			ret = sql_exec_simple(exit_sql[i]);
			i--;
		}
	}
	return ret;
}

static int configdb_exit(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(exit_sql[i]);
	}
	return ret;
}

int configdb_count_table(const char *tbl, int *num)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "SELECT count(oid) AS num FROM %s;", tbl);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num);
	free(sql);

	return ret;
}

int configdb_add_host(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		"INSERT INTO hosts (nqn, ctime) "
		"VALUES ('%s', CURRENT_TIMESTAMP);",
		nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

int configdb_del_host(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "DELETE FROM hosts WHERE nqn = '%s';", nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_add_subsys(const char *subsysnqn, uint32_t subsys_id, int type)
{
	char *sql;
	char serial[32];
	int ret, allow_any = 0;

	sprintf(serial, "SHEEPDOG%06x", subsys_id);
	if (type == NVME_NQN_CUR)
		allow_any = 1;
	ret = asprintf(&sql,
		       "INSERT INTO subsystems "
		       "(nqn, attr_vid, attr_model, attr_serial, "
		       "attr_version, attr_ieee_oui, attr_firmware, "
		       "attr_allow_any_host, attr_type, attr_qid_max, ctime) "
		       "VALUES ('%s', '%d', 'sheepdog', '%s', '2.4', "
		       "'851255', '%s', '%d', '%d', '%d', CURRENT_TIMESTAMP);",
		       subsysnqn, subsys_id, serial, firmware_rev, allow_any,
		       type, NVMF_NUM_QUEUES);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_get_discovery_nqn(char *nqn)
{
	return sql_exec_str("SELECT nqn FROM subsystems WHERE attr_type = '3';",
			    "nqn", nqn);
}

int configdb_set_discovery_nqn(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		"UPDATE subsystems SET nqn = '%s' WHERE attr_type = '3';",
		nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_get_subsys_attr(const char *nqn, const char *attr, char *buf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, "SELECT %s FROM subsystems WHERE nqn = '%s';",
		       attr, nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

int configdb_set_subsys_attr(const char *nqn, const char *attr,
			     const char *buf)
{
	char *sql;
	int ret;

	if (!strcmp(attr, "attr_type"))
		return -EPERM;
	if (!strcmp(attr, "attr_qid_max")) {
		unsigned long qid_max;
		char *eptr = NULL;

		qid_max = strtoul(buf, &eptr, 10);
		if (qid_max == ULONG_MAX || buf == eptr)
			return -EINVAL;
		if (qid_max > NVMF_NUM_QUEUES)
			return -EINVAL;
	}
	if (!strcmp(attr, "attr_cntlid_min") ||
	    !strcmp(attr, "attr_cntlid_max")) {
		unsigned long lim;
		char *eptr = NULL;

		lim = strtoul(buf, &eptr, 10);
		if (lim == ULONG_MAX || buf == eptr)
			return -EINVAL;
		if (lim < NVME_CNTLID_MIN || lim > NVME_CNTLID_MAX)
			return -EINVAL;
	}
	ret = asprintf(&sql,
		"UPDATE subsystems SET %s = '%s' WHERE nqn = '%s';",
		attr, buf, nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	if (sqlite3_changes(configdb_db) == 0)
		ret = -EPERM;
	return ret;
}

int configdb_del_subsys(uint32_t subsys_id)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "DELETE FROM subsystems WHERE attr_vid = '%d';",
		       subsys_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static int raise_aen_cb(void *argp, int argc, char **argv, char **col)
{
	char nqn[MAX_NQN_SIZE + 1] = {};
	int *type = argp, i;
	unsigned long cntlid = 0;

	for (i = 0; i < argc; i++) {
		if (!argv[i] || !strlen(argv[i]))
			continue;
		if (!strcmp(col[i], "cntlid")) {
			char *eptr = NULL;

			cntlid = strtoul(argv[i], &eptr, 10);
			if (cntlid == ULONG_MAX || argv[i] == eptr) {
				cntlid = 0;
				continue;
			}
		}
		if (!strcmp(col[i], "subsysnqn"))
			strcpy(nqn, argv[i]);
	}
	if (cntlid > 0)
		raise_aen(nqn, cntlid, *type);

	return 0;
}

static int raise_ns_chg_aen(uint32_t subsys_id, uint32_t nsid)
{
	char *sql, *errmsg;
	int type = NVME_AER_NOTICE_NS_CHANGED;
	int ret;

	ret = asprintf(&sql,
		       "SELECT s.nqn AS subsysnqn, c.cntlid FROM controllers AS c "
		       "INNER JOIN subsystems AS s ON c.subsys_id = s.oid "
		       "INNER JOIN namespaces AS n ON n.subsys_id = s.oid "
		       "WHERE s.attr_vid = '%d' AND n.nsid = '%d';",
		       subsys_id, nsid);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, raise_aen_cb, &type, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

int configdb_add_namespace(uint32_t subsys_id, uint32_t nsid,
			   uuid_t uuid, uint32_t agid)
{
	char *sql;
	char uuid_str[65], nguid_str[33];
	int ret;

	uuid_unparse(uuid, uuid_str);
	sprintf(nguid_str, "%08x000efd3700000000%08x",
		subsys_id, nsid);
	ret = asprintf(&sql, "INSERT INTO namespaces "
		       "(device_uuid, device_nguid, nsid, "
		       "subsys_id, ana_group_id, ctime) "
		       "SELECT '%s', '%s', '%u', s.oid, ag.id, CURRENT_TIMESTAMP "
		       "FROM subsystems AS s, ana_groups AS ag "
		       "WHERE s.attr_vid = '%d' AND s.attr_type == '2' AND ag.id = '%u';",
		       uuid_str, nguid_str, nsid, subsys_id, agid);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		return ret;
	ret = raise_ns_chg_aen(subsys_id, nsid);
	sql_exec_simple("SELECT * FROM namespaces;");
	return ret;
}

#define PARSE_COL(i, l, v)				\
	if (!strcmp(argv[i], l)) {			\
		(v) = strtoul(argv[i], &e, 10);		\
		if (argv[i] == e) {			\
			(v) = 0; goto parse_error;	\
		}					\
	}

static int lookup_namespace_cb(void *argp, int argc, char **argv, char **col)
{
	struct nofuse_namespace *ns = argp;
	char *e = NULL;
	int i;

	for (i = 0; i < argc; i++) {
		if (!argv[i] || !strlen(argv[i]))
			continue;
		PARSE_COL(i, "nsid", ns->nsid);
		PARSE_COL(i, "ana_group_id", ns->ana_grpid);
		PARSE_COL(i, "device_size", ns->size);
		PARSE_COL(i, "device_blksize", ns->blksize);
		if (!strcmp(col[i], "device_enable")) {
			if (!strcmp(argv[i], "1"))
				ns->enabled = true;
		}
		if (!strcmp(col[i], "device_readonly")) {
			if (!strcmp(argv[i], "1"))
				ns->readonly = true;
		}
	}
	return 0;
parse_error:
	sd_err("parsing error on '%s': value '%s'", col[i], argv[i]);
	return 1;
}

int configdb_lookup_namespace(const char *subsysnqn, uint32_t nsid,
			      struct nofuse_namespace *ns)
{
	int ret;
	char *sql, *errmsg;

	ret = asprintf(&sql,
		       "SELECT nsid, ana_group_id, device_size, "
		       "device_readonly, device_blksize FROM namespaces AS n "
		       "INNER JOIN subsystems AS s ON s.oid = n.subsys_id "
		       "WHERE s.nqn = '%s' and n.nsid = '%d';",
		       subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, lookup_namespace_cb, ns, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

int configdb_get_namespace_attr(uint32_t subsys_id, uint32_t nsid,
				const char *attr, char *buf)
{
	int ret;
	char *sql;

	if (!strcmp(attr, "enable"))
		attr = "device_enable";
	ret = asprintf(&sql,
		       "SELECT ns.%s FROM namespaces AS n "
		       "INNER JOIN subsystems AS s ON s.oid = n.subsys_id "
		       "WHERE s.attr_vid = '%d' AND n.nsid = '%u';",
		       attr, subsys_id, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

int configdb_set_namespace_attr(uint32_t subsys_id, uint32_t nsid,
				const char *attr, const char *buf)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	if (!strcmp(attr, "enable"))
		attr = "device_enable";
	ret = asprintf(&sql,
		       "UPDATE namespaces SET %s = '%s' FROM "
		       "(SELECT n.nsid AS nsid, s.nqn AS nqn, s.attr_vid AS vid "
		       "FROM namespaces AS n "
		       "INNER JOIN subsystems AS s ON s.oid = n.subsys_id) AS sel "
		       "WHERE sel.vid = '%d' AND sel.nsid = '%u';",
		       attr, buf, subsys_id, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	if (sqlite3_changes(configdb_db) == 0) {
		sd_warn("%s: no rows modified", __func__);
		goto done;
	}
done:
	COMMIT_TRANSACTION;
	if (!ret)
		raise_ns_chg_aen(subsys_id, nsid);
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_get_namespace_anagrp(const char *subsysnqn, uint32_t nsid,
				  int *agid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "SELECT ag.id AS grpid FROM ana_groups AS ag "
		       "INNER JOIN namespaces AS n ON n.ana_group_id = ag.id "
		       "INNER JOIN subsystems AS s ON s.oid = n.subsys_id "
		       "WHERE s.nqn = '%s' AND n.nsid = '%u';",
		       subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "grpid", agid);
	free(sql);
	return ret;
}

int configdb_set_namespace_anagrp(const char *subsysnqn, uint32_t nsid,
				  int ana_grpid)
{
	char *sql, *errmsg;
	int ret, _ret, new_ana_grpid;
	int type = NVME_AER_NOTICE_ANA;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	ret = asprintf(&sql,
		       "UPDATE namespaces SET ana_group_id = sel.grpid "
		       "FROM "
		       "(SELECT ag.id AS grpid "
		       "FROM ana_groups AS ag) AS sel "
		       "WHERE sel.grpid = '%d' AND nsid = '%u';",
		       ana_grpid, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = configdb_get_namespace_anagrp(subsysnqn, nsid,
					    &new_ana_grpid);
	if (ret < 0)
		goto rollback;
	if (new_ana_grpid != ana_grpid) {
		sd_warn("%s: ana group id %d should be %d",
			__func__, new_ana_grpid, ana_grpid);
		ret = -ENOENT;
	}
	COMMIT_TRANSACTION;

	ret = asprintf(&sql,
		"SELECT subsys_nqn AS subsysnqn, cntlid FROM subsys_ctrl "
		       "WHERE subsys_nqn = '%s';", subsysnqn);
	if (ret < 0)
		return 0;
	ret = sqlite3_exec(configdb_db, sql, raise_aen_cb, &type, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return 0;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_del_namespace(uint32_t subsys_id, uint32_t nsid)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	ret = asprintf(&sql,
		       "DELETE FROM namespaces AS n WHERE n.subsys_id IN "
		       "(SELECT oid FROM subsystems WHERE attr_vid = '%d') AND "
		       "n.nsid = '%u';", subsys_id, nsid);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	if (sqlite3_changes(configdb_db) == 0) {
		sd_warn("%s: no rows deleted", __func__);
		ret = -ENOENT;
		goto done;
	}
done:
	COMMIT_TRANSACTION;
	if (!ret)
		raise_ns_chg_aen(subsys_id, nsid);
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_add_ctrl(const char *subsysnqn, int cntlid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "INSERT INTO controllers ( cntlid, subsys_id ) "
		       "SELECT '%d', s.oid FROM subsystems AS s "
		       "WHERE s.nqn = '%s';", cntlid, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_get_cntlid(const char *subsysnqn, uint16_t *cntlid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "SELECT cntlid_next FROM subsystems WHERE nqn = '%s';",
		       subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "cntlid_next", (int *)cntlid);
	free(sql);

	return ret;
}

int configdb_del_ctrl(const char *subsysnqn, int cntlid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "DELETE FROM controllers AS c WHERE c.subsys_id IN "
		       "(SELECT oid FROM subsystems WHERE nqn = '%s') AND "
		       "c.cntlid = '%d';",
		       subsysnqn, cntlid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_add_port(unsigned int portid, const char *traddr,
		      const char *adrfam, unsigned int trsvcid)
{
	char *sql;
	int ret;

	if (!portid) {
		sd_err("no port id specified");
		return -EINVAL;
	}

	ret = asprintf(&sql,
		       "INSERT INTO ports (id, addr_traddr, addr_adrfam, addr_trsvcid, ctime)"
		       " VALUES ('%d', '%s', '%s', '%u', CURRENT_TIMESTAMP);",
		       portid, traddr, adrfam, trsvcid);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_get_port_attr(unsigned int port, const char *attr, char *buf)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "SELECT %s FROM ports WHERE id = '%d';", attr, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

int configdb_set_port_attr(unsigned int port, const char *attr,
			   const char *value)
{
	char *sql;
	int ret;

	if (!strcmp(attr, "addr_trtype")) {
		if (strcmp(value, "tcp")) {
			return -EINVAL;
		}
	} else if (!strcmp(attr, "addr_adrfam")) {
		if (strcmp(value, ADRFAM_STR_IPV4) &&
		    strcmp(value, ADRFAM_STR_IPV6))
			return -EINVAL;
	} else if (!strcmp(attr, "addr_tsas")) {
		if (strcmp(value, "tls1.3") &&
		    strcmp(value, "none"))
			return -EINVAL;
	} else if (!strcmp(attr, "addr_treq")) {
		if (strcmp(value, "not required") &&
		    strcmp(value, "required") &&
		    strcmp(value, "not specified"))
			return -EINVAL;
	}

	ret = asprintf(&sql,
		       "UPDATE ports SET %s = '%s' WHERE id = '%d';",
		       attr, value, port);
	if (ret < 0) {
		return ret;
	}
	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql,
		       "UPDATE hosts SET genctr = genctr + 1 "
		       "FROM "
		       "(SELECT hs.host_id AS host_id, sp.port_id AS port_id "
		       "FROM host_subsys AS hs "
		       "INNER JOIN subsys_port AS sp ON hs.subsys_id = sp.subsys_id) "
		       "AS hg WHERE hg.host_id = hosts.oid AND hg.port_id = '%d';",
		       port);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_del_port(unsigned int portid)
{
	char *sql;
	int ret, portnum = 0;

	ret = configdb_count_subsys_port(portid, &portnum);
	if (ret < 0)
		return ret;
	if (portnum > 0)
		return -EBUSY;
	ret = asprintf(&sql, "DELETE FROM ports WHERE id = '%d';", portid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static int raise_ana_port_chg_aen(unsigned int portid)
{
	char *sql, *errmsg;
	int type = NVME_AER_NOTICE_ANA;
	int ret;

	ret = asprintf(&sql,
		       "SELECT s.nqn AS subsysnqn, c.cntlid FROM controllers AS c "
		       "INNER JOIN subsystems AS s ON c.subsys_id = s.oid "
		       "INNER JOIN subsys_port AS sp ON sp.subsys_id = s.oid "
		       "WHERE sp.port_id = '%d';", portid);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, raise_aen_cb, &type, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

int configdb_add_ana_group(unsigned int grpid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, "INSERT INTO ana_groups (id) VALUES ('%d');",
		       grpid);

	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_del_ana_group(unsigned int grpid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, "DELETE FROM ana_groups WHERE id = '%d';",
		       grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_add_ana_port_group(unsigned int portid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "INSERT INTO ana_port_group (ana_group_id, port_id, ana_state, ctime) "
		       "SELECT ag.id, p.id, '%d', CURRENT_TIMESTAMP "
		       "FROM ports AS p, ana_groups AS ag "
		       "WHERE p.id = '%d' AND ag.id = p.id;",
		       NVME_ANA_OPTIMIZED, portid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	ret = asprintf(&sql,
		       "INSERT INTO ana_port_group (ana_group_id, port_id, ana_state, ctime) "
		       "SELECT ag.id, p.id, '%d', CURRENT_TIMESTAMP "
		       "FROM ports AS p, ana_groups AS ag "
		       "WHERE p.id = '%d' AND ag.id != p.id;",
		       NVME_ANA_NONOPTIMIZED, portid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	raise_ana_port_chg_aen(portid);
	return ret;
}

int configdb_get_ana_port_group(unsigned int portid, const char *ana_grpid,
				int *ana_state)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "SELECT ap.ana_state AS ana_state FROM ana_port_group AS ap "
		       "INNER JOIN ports AS p ON p.id = ap.port_id "
		       "INNER JOIN ana_groups AS ag ON ag.id = ap.ana_group_id "
		       "WHERE p.id = '%d' AND ag.id = '%s';",
		       portid, ana_grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "ana_state", ana_state);
	free(sql);
	return ret;
}

int configdb_set_ana_port_group(unsigned int portid, const char *ana_grpid,
				int ana_state)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "UPDATE ana_port_group SET ana_state = '%d', chgcnt = chgcnt + 1 "
		       "FROM "
		       "(SELECT ap.id AS ag_id, ap.port_id AS port_id, ag.id AS grpid "
		       " FROM ana_port_group AS ap "
		       " INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id) AS sel "
		       "WHERE id = sel.ag_id AND sel.port_id = '%d' AND sel.grpid = '%s';",
		       ana_state, portid, ana_grpid);
	if (ret < 0)
		return 0;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		return 0;
	raise_ana_port_chg_aen(portid);
	return 0;
}

int configdb_del_ana_port_group(unsigned int portid, int grpid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "DELETE FROM ana_port_group AS ap WHERE ap.port_id IN "
		       "(SELECT id FROM ports WHERE id = '%d') AND "
		       "ap.ana_group_id IN "
		       "(SELECT id FROM ana_groups WHERE id = '%d');",
		       portid, grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	raise_ana_port_chg_aen(portid);
	return ret;
}

static char raise_disc_chg_aen_sql[] =
	"SELECT c.cntlid FROM controllers AS c "
	"INNER JOIN subsystems AS s ON s.oid = c.subsys_id "
	"WHERE s.attr_type = '3';";

static int raise_disc_chg_aen(void)
{
	char *errmsg;
	int type = NVME_AER_NOTICE_DISC_CHANGED;
	int ret;

	ret = sqlite3_exec(configdb_db, raise_disc_chg_aen_sql,
			   raise_aen_cb, &type, &errmsg);
	return sql_exec_error(ret, raise_disc_chg_aen_sql, errmsg);
}

int configdb_add_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "INSERT INTO host_subsys (host_id, subsys_id, ctime) "
		       "SELECT h.oid, s.oid, CURRENT_TIMESTAMP FROM hosts AS h, subsystems AS s "
		       "WHERE h.nqn = '%s' AND s.nqn = '%s' AND s.attr_allow_any_host != '1';",
		       hostnqn, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	if (!ret)
		raise_disc_chg_aen();
	return ret;
}

int configdb_count_host_subsys(const char *subsysnqn, int *num_hosts)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "SELECT count(hs.host_id) AS num FROM host_subsys AS hs "
		       "INNER JOIN subsystems AS s ON s.oid = hs.subsys_id "
		       "WHERE s.nqn = '%s';", subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num_hosts);
	free(sql);
	return ret;
}

int configdb_del_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	int ret;
	char *sql;

	ret = asprintf(&sql,
		       "DELETE FROM host_subsys AS hs "
		       "WHERE hs.host_id IN "
		       "(SELECT oid FROM hosts WHERE nqn = '%s') AND "
		       "hs.subsys_id IN "
		       "(SELECT oid FROM subsystems WHERE nqn = '%s');",
		       hostnqn, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		return ret;
	if (sqlite3_changes(configdb_db) == 0)
		return -EINVAL;

	raise_disc_chg_aen();
	return 0;
}

static int configdb_update_subsys_port_genctr(const char *subsysnqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "UPDATE hosts SET genctr = genctr + 1 "
		       "FROM "
		       "(SELECT s.nqn AS subsys_nqn, hs.host_id AS host_id "
		       "FROM host_subsys AS hs "
		       "INNER JOIN subsystems AS s ON s.oid = hs.subsys_id) AS hs "
		       "WHERE hs.host_id = hosts.oid AND hs.subsys_nqn = '%s';",
		       subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

int configdb_add_subsys_port(const char *subsysnqn, unsigned int port)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql,
		       "INSERT INTO subsys_port (subsys_id, port_id, ctime) "
		       "SELECT s.oid, p.id, CURRENT_TIMESTAMP FROM subsystems AS s, ports AS p "
		       "WHERE s.nqn = '%s' AND p.id = '%d';",
		       subsysnqn, port);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = configdb_update_subsys_port_genctr(subsysnqn);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	raise_disc_chg_aen();
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_del_subsys_port(const char *subsysnqn, unsigned int port)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql,
		       "DELETE FROM subsys_port AS sp "
		       "WHERE sp.subsys_id in "
		       "(SELECT oid FROM subsystems WHERE nqn LIKE '%s') AND "
		       "sp.port_id IN "
		       "(SELECT id FROM ports WHERE id = %d);",
		       subsysnqn, port);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = configdb_update_subsys_port_genctr(subsysnqn);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	raise_disc_chg_aen();
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_count_subsys_port(unsigned int port, int *portnum)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "SELECT count(p.id) AS portnum "
		       "FROM subsys_port AS sp "
		       "INNER JOIN subsystems AS s ON s.oid = sp.subsys_id "
		       "INNER JOIN ports AS p ON p.id = sp.port_id "
		       "WHERE p.id = '%d';", port);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "portnum", portnum);
	free(sql);
	return ret;
}

int configdb_check_allowed_host(const char *hostnqn, const char *subsysnqn,
				unsigned int portid)
{
	int ret, num = 0;
	char *sql;

	ret = asprintf(&sql,
		       "SELECT count(s.nqn) AS subsys_num "
		       "FROM subsys_port AS sp "
		       "INNER JOIN subsystems AS s ON s.oid = sp.subsys_id "
		       "INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
		       "INNER JOIN hosts AS h ON hs.host_id = h.oid "
		       "INNER JOIN ports AS p ON sp.port_id = p.id "
		       "WHERE h.nqn = '%s' AND s.nqn = '%s' AND p.id = '%d';",
		       hostnqn, subsysnqn, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "subsys_num", &num);
	free(sql);
	if (!ret && num > 0) {
		sd_debug("host %s allowed from subsys %s",
			 hostnqn, subsysnqn);
		return num;
	}
	ret = asprintf(&sql,
		       "SELECT count(s.nqn) AS subsys_num "
		       "FROM subsys_port AS sp "
		       "INNER JOIN subsystems AS s ON s.oid = sp.subsys_id "
		       "INNER JOIN ports AS p ON sp.port_id = p.id "
		       "WHERE s.attr_allow_any_host = '1' "
		       "AND s.nqn = '%s' AND p.id = '%d';",
		       subsysnqn, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "subsys_num", &num);
	free(sql);
	if (ret < 0)
		return ret;
	if (num > 0)
		sd_debug("any host allowed from subsys %s",
			 subsysnqn);
	return num;
}

struct sql_entry_parm {
	uint8_t *buffer;
	int cur;
	int len;
};

static int sql_disc_entry_cb(void *argp, int argc, char **argv, char **colname)
{
	int i;
	struct sql_entry_parm *parm = argp;
	struct nvmf_disc_rsp_page_entry *entry;

	if (!argp) {
		sd_err("%s: Invalid parameter", __func__);
		return 0;
	}
	if (!parm->buffer)
		goto next;
	entry = (struct nvmf_disc_rsp_page_entry *)(parm->buffer + parm->cur);
	if (parm->cur >= parm->len)
		goto next;

	memset(entry, 0, sizeof(*entry));
	entry->cntlid = (uint16_t)NVME_CNTLID_DYNAMIC;
	entry->asqsz = htole16(NVMF_AQ_DEPTH);
	entry->subtype = NVME_NQN_NVM;
	entry->treq = NVMF_TREQ_NOT_SPECIFIED;
	entry->tsas.tcp.sectype = NVMF_TCP_SECTYPE_NONE;

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;

		if (!strcmp(colname[i], "subsys_nqn")) {
			if (arg_len > NVMF_NQN_FIELD_LEN)
				arg_len = NVMF_NQN_FIELD_LEN;
			strncpy(entry->subnqn, argv[i], arg_len);
		} else if (!strcmp(colname[i], "id")) {
			char *eptr = NULL;
			int val;

			val = strtol(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			entry->portid = htole16(val);
		} else if (!strcmp(colname[i], "subtype")) {
			char *eptr = NULL;
			int val;

			val = strtol(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			entry->subtype = val;
		} else if (!strcmp(colname[i], "adrfam")) {
			if (!strcmp(argv[i], ADRFAM_STR_IPV4)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP4;
			} else if (!strcmp(argv[i], ADRFAM_STR_IPV6)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP6;
			} else if (!strcmp(argv[i], ADRFAM_STR_FC)) {
				entry->adrfam = NVMF_ADDR_FAMILY_FC;
			} else if (!strcmp(argv[i], ADRFAM_STR_IB)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IB;
			} else if (!strcmp(argv[i], ADRFAM_STR_PCI)) {
				entry->adrfam = NVMF_ADDR_FAMILY_PCI;
			} else {
				entry->adrfam = NVMF_ADDR_FAMILY_LOOP;
			}
		} else if (!strcmp(colname[i], "trtype")) {
			if (!strcmp(argv[i], "tcp")) {
				entry->trtype = NVMF_TRTYPE_TCP;
			} else if (!strcmp(argv[i], "fc")) {
				entry->trtype = NVMF_TRTYPE_FC;
			} else if (!strcmp(argv[i], "rdma")) {
				entry->trtype = NVMF_TRTYPE_RDMA;
			} else {
				entry->trtype = NVMF_TRTYPE_LOOP;
			}
		} else if (!strcmp(colname[i], "traddr")) {
			if (!arg_len) {
				memset(entry->traddr, 0,
				       NVMF_NQN_FIELD_LEN);
				continue;
			}
			if (arg_len > NVMF_NQN_FIELD_LEN)
				arg_len = NVMF_NQN_FIELD_LEN;
			memcpy(entry->traddr, argv[i], arg_len);
		} else if (!strcmp(colname[i], "trsvcid")) {
			if (!arg_len) {
				memset(entry->trsvcid, 0,
				       NVMF_TRSVCID_SIZE);
				continue;
			}
			if (arg_len > NVMF_TRSVCID_SIZE)
				arg_len = NVMF_TRSVCID_SIZE;
			memcpy(entry->trsvcid, argv[i], arg_len);
		} else if (!strcmp(colname[i], "treq")) {
			if (arg_len &&
			    !strcmp(argv[i], "required")) {
				entry->treq = NVMF_TREQ_REQUIRED;
			} else if (arg_len &&
				   !strcmp(argv[i], "not required")) {
				entry->treq = NVMF_TREQ_NOT_REQUIRED;
			}
		} else if (!strcmp(colname[i], "tsas")) {
			if (arg_len && !strcmp(argv[i], "tls1.3")) {
				entry->tsas.tcp.sectype =
					NVMF_TCP_SECTYPE_TLS13;
			} else {
				entry->tsas.tcp.sectype =
					NVMF_TCP_SECTYPE_NONE;
			}
		} else {
			sd_warn("skip discovery type '%s'",
				colname[i]);
		}
	}
	if (entry->trtype == NVMF_TRTYPE_LOOP)
		entry->adrfam = NVMF_ADDR_FAMILY_LOOP;
	if (entry->trtype == NVMF_TRTYPE_FC)
		entry->adrfam = NVMF_ADDR_FAMILY_FC;
	if (entry->trtype == NVMF_TRTYPE_TCP &&
	    (entry->adrfam != NVMF_ADDR_FAMILY_IP4 &&
	     entry->adrfam != NVMF_ADDR_FAMILY_IP6)) {
		if (strchr(entry->traddr, ':'))
			entry->adrfam = NVMF_ADDR_FAMILY_IP6;
		else
			entry->adrfam = NVMF_ADDR_FAMILY_IP4;
	}
	if (!strlen(entry->traddr)) {
		sd_err("Empty discovery record (%d, %d)",
		       entry->portid, entry->trtype);
		return 0;
	}
next:
	parm->cur += sizeof(struct nvmf_disc_rsp_page_entry);
	return 0;
}

static char any_disc_entry_sql[] =
	"SELECT s.nqn AS subsys_nqn, "
	"p.id, s.attr_type AS subtype, p.addr_trtype AS trtype, "
	"p.addr_traddr AS traddr, p.addr_trsvcid AS trsvcid, "
	"p.addr_treq AS treq, p.addr_tsas AS tsas "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.oid = sp.subsys_id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE s.attr_allow_any_host = '1';";

int configdb_host_disc_entries(const char *hostnqn, uint8_t *log, int log_len)
{
	struct sql_entry_parm parm = {
		.buffer = log,
		.cur = 0,
		.len = log_len,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql,
		       "SELECT s.nqn AS subsys_nqn, "
		       "p.id, s.attr_type AS subtype, p.addr_trtype AS trtype, "
		       "p.addr_traddr AS traddr, p.addr_trsvcid AS trsvcid, "
		       "p.addr_treq AS treq, p.addr_tsas AS tsas "
		       "FROM subsys_port AS sp "
		       "INNER JOIN subsystems AS s ON s.oid = sp.subsys_id "
		       "INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
		       "INNER JOIN hosts AS h ON hs.host_id = h.oid "
		       "INNER JOIN ports AS p ON sp.port_id = p.id "
		       "WHERE h.nqn LIKE '%s';", hostnqn);
	if (ret < 0)
		return ret;
	sd_debug("Display disc entries for %s", hostnqn);
	ret = sqlite3_exec(configdb_db, sql, sql_disc_entry_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	sd_debug("disc entries: cur %d len %d", parm.cur, parm.len);

	sd_debug("Display disc entries for any host");
	ret = sqlite3_exec(configdb_db, any_disc_entry_sql,
			   sql_disc_entry_cb, &parm, &errmsg);
	ret = sql_exec_error(ret, any_disc_entry_sql, errmsg);
	sd_debug("disc entries: cur %d len %d", parm.cur, parm.len);
	return parm.cur;
}

int configdb_host_genctr(const char *hostnqn, int *genctr)
{
	char *sql;
	int ret;

	ret = asprintf(&sql,
		       "SELECT genctr FROM hosts WHERE nqn LIKE '%s';",
		       hostnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "genctr", genctr);
	free(sql);
	return ret;
}

static int subsys_identify_ctrl_cb(void *p, int argc, char **argv, char **col)
{
	struct nvme_id_ctrl *id = p;
	int i;

	for (i = 0; i < argc; i++) {
		if (!argv[i])
			continue;
		if (!strcmp(col[i], "nqn")) {
			strcpy(id->subnqn, argv[i]);
		} else if (!strcmp(col[i], "firmware")) {
			strcpy(id->fr, argv[i]);
		} else if (!strcmp(col[i], "model")) {
			memcpy(id->mn, argv[i], strlen(argv[i]));
		} else if (!strcmp(col[i], "serial")) {
			memcpy(id->sn, argv[i], strlen(argv[i]));
		} else if (!strcmp(col[i], "ieee_oui")) {
			uint32_t oui, oui_le;
			char *eptr = NULL;

			oui = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			oui_le = htole32(oui & 0xfff);
			memcpy(id->ieee, &oui_le, sizeof(id->ieee));
		} else if (!strcmp(col[i], "type")) {
			if (!strcmp(argv[i], "2"))
				id->cntrltype = NVME_CTRL_CNTRLTYPE_IO;
			else
				id->cntrltype = NVME_CTRL_CNTRLTYPE_DISC;
		} else if (!strcmp(col[i], "version")) {
			int maj, min;

			if (sscanf(argv[i], "%d.%d", &maj, &min) != 2) {
				maj = 2;
				min = 0;
			}
			id->ver = htole32((maj & 0xff) << 16 | (min & 0xff) << 8);
		}
	}
	return 0;
}

int configdb_subsys_identify_ctrl(const char *subsysnqn,
				  struct nvme_id_ctrl *id)
{
	int ret;
	char *sql, *errmsg;

	ret = asprintf(&sql,
		       "SELECT s.nqn, s.attr_firmware AS firmware, "
		       "s.attr_ieee_oui AS ieee_oui, s.attr_model AS model, "
		       "s.attr_serial AS serial, s.attr_type AS type, "
		       "s.attr_version AS version "
		       "FROM subsystems AS s WHERE s.nqn = '%s';",
		       subsysnqn);
	if (ret < 0)
		return ret;

	ret = sqlite3_exec(configdb_db, sql, subsys_identify_ctrl_cb,
			   id, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static int ns_list_cb(void *argp, int argc, char **argv, char **col)
{
	struct sql_entry_parm *parm = argp;
	int i;

	if (!argp) {
		sd_warn("%s: Invalid parameter", __func__);
		return 0;
	}

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;

		if (!strcmp(col[i], "nsid")) {
			void *buf = parm->buffer + parm->cur;
			char *eptr = NULL;
			uint32_t nsid, _nsid = 0;

			if (!arg_len)
				continue;

			_nsid = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				sd_warn("%s: parsing error on 'nsid'",
					__func__);
				_nsid = 0;
				continue;
			}
			nsid = htole32(_nsid);
			memcpy(buf, &nsid, sizeof(uint32_t));
			parm->cur += sizeof(uint32_t);
		}
	}
	return 0;
}

int configdb_identify_active_ns(const char *subsysnqn,
				uint8_t *ns_list, size_t len)
{
	struct sql_entry_parm parm = {
		.len = len,
		.buffer = ns_list,
		.cur = 0,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql,
		       "SELECT ns.nsid FROM namespaces AS n "
		       "INNER JOIN subsystems AS s ON n.subsys_id = s.oid "
		       "WHERE s.nqn = '%s' AND n.device_enable = '1' "
		       "ORDER BY n.nsid;", subsysnqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, ns_list_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static int count_ana_grps_cb(void *argp, int argc, char **argv, char **col)
{
	int i;
	struct nvme_ana_group_desc *grp_desc = argp;
	unsigned int ana_state = 0xff, chgcnt = 0, num = 0;

	if (!argp) {
		sd_err("%s: Invalid parameter", __func__);
		return 0;
	}

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;
		char *eptr = NULL;

		if (!arg_len) {
			continue;
		}
		if (!strcmp(col[i], "ana_state")) {
			ana_state = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				sd_warn("%s: parsing error on 'state'",
					__func__);
				ana_state = 0xff;
				continue;
			}
		}
		if (!strcmp(col[i], "chgcnt")) {
			chgcnt = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				sd_warn("%s: parsing error on 'chgcnt'",
					__func__);
				continue;
			}
		}
		if (!strcmp(col[i], "num")) {
			num = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				sd_warn("%s: parsing error on 'nsid'",
					__func__);
				num = 0;
				continue;
			}
		}
	}
	if (ana_state != 0xff && num != 0) {
		grp_desc->chgcnt = htole64(chgcnt);
		grp_desc->state = ana_state;
		grp_desc->nnsids = htole32(num);
	}
	return 0;
}

int configdb_ana_log_entries(const char *subsysnqn, unsigned int portid,
			     uint8_t *log, int log_len)
{
	struct nvme_ana_rsp_hdr *hdr = (struct nvme_ana_rsp_hdr *)log;
	struct nvme_ana_group_desc *grp_desc = hdr->entries;
	struct sql_entry_parm parm;
	char *sql, *errmsg;
	int ret, ngrps = 0, grpid;

	memset(grp_desc, 0, 32);
	parm.buffer = (uint8_t *)grp_desc;
	parm.len = log_len - sizeof(struct nvme_ana_rsp_hdr);
	for (grpid = 1; grpid <= MAX_ANAGRPID; grpid++) {
		uint32_t nnsids;

		parm.buffer = (uint8_t *)grp_desc;
		ret = asprintf(&sql,
			       "SELECT ap.ana_state, ap.chgcnt, count(n.nsid) AS num "
			       "FROM ana_port_group AS ap "
			       "INNER JOIN subsys_port AS sp ON sp.port_id = ap.port_id "
			       "INNER JOIN subsystems AS s ON sp.subsys_id = s.oid "
			       "INNER JOIN namespaces AS n ON n.subsys_id = s.oid "
			       "INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id "
			       "WHERE s.nqn = '%s' AND ap.port_id = '%d' AND ag.id = '%d';",
			       subsysnqn, portid, grpid);
		if (ret < 0)
			return ret;
		ret = sqlite3_exec(configdb_db, sql, count_ana_grps_cb,
				   parm.buffer, &errmsg);
		ret = sql_exec_error(ret, sql, errmsg);
		free(sql);
		if (ret < 0)
			return ret;
		nnsids = le32toh(grp_desc->nnsids);
		if (!nnsids)
			continue;

		grp_desc->grpid = htole16(grpid);
		sd_debug("%s: grpid %u %d nsids state %d",
			 __func__, grpid, nnsids, grp_desc->state);

		parm.len -= sizeof(struct nvme_ana_group_desc);
		parm.buffer = (uint8_t *)grp_desc->nsids;
		parm.cur = 0;
		ret = asprintf(&sql,
			       "SELECT ns.nsid FROM ana_port_group AS ap "
			       "INNER JOIN subsys_port AS sp ON sp.port_id = ap.port_id "
			       "INNER JOIN subsystems AS s ON sp.subsys_id = s.oid "
			       "INNER JOIN namespaces AS n ON n.subsys_id = s.oid "
			       "INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id "
			       "WHERE s.nqn = '%s' AND ap.port_id = '%d' AND ag.id = '%d';",
			       subsysnqn, portid, grpid);
		if (ret < 0)
			return ret;
		ret = sqlite3_exec(configdb_db, sql, ns_list_cb,
				   &parm, &errmsg);
		ret = sql_exec_error(ret, sql, errmsg);
		free(sql);
		if (ret < 0)
			return ret;
		grp_desc = (struct nvme_ana_group_desc *)
			(parm.buffer + parm.cur);
		parm.len -= parm.cur;
		memset(grp_desc, 0, sizeof(*grp_desc));
		ngrps++;
		if (parm.len < 32)
			break;
	}
	hdr->ngrps = htole16(ngrps);
	sd_debug("%s: %d ana groups", __func__, ngrps);
	return parm.len;
}

int configdb_ns_changed_log_entries(const char *subsysnqn, uint16_t cntlid,
				    uint8_t *log, int log_len)
{
	struct sql_entry_parm parm = {
		.len = log_len,
		.buffer = log,
		.cur = 0,
	};
	char *sql, *errmsg;
	int ret, _ret;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret)
		return ret;

	ret = asprintf(&sql,
		       "SELECT chg.nsid FROM ns_changed AS chg "
		       "INNER JOIN controllers AS c ON c.oid = chg.ctrl_id "
		       "INNER JOIN subsystems AS s ON s.oid = c.subsys_id "
		       "WHERE s.nqn = '%s' AND c.cntlid = '%d';",
		       subsysnqn, cntlid);
	if (ret < 0)
		goto rollback;
	ret = sqlite3_exec(configdb_db, sql, ns_list_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	if (ret < 0)
		goto rollback;
	ret = asprintf(&sql,
		       "DELETE FROM ns_changed AS chg WHERE chg.ctrl_id IN "
		       "(SELECT ctrl_id FROM subsys_ctrl AS sc "
		       " WHERE sc.subsys_nqn = '%s' AND sc.cntlid = '%d');",
		       subsysnqn, cntlid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	COMMIT_TRANSACTION;
	return parm.cur;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

int configdb_open(const char *filename)
{
	int ret;

	ret = sqlite3_open(filename, &configdb_db);
	if (ret) {
		sd_err("Can't open database: %s",
		       sqlite3_errmsg(configdb_db));
		sqlite3_close(configdb_db);
		return -ENOENT;
	}
	ret = configdb_init();
	if (ret) {
		sd_err("Can't initialize database, error %d", ret);
		sqlite3_close(configdb_db);
	}
	return ret;
}

void configdb_close(const char *filename)
{
	configdb_exit();
	sqlite3_close(configdb_db);
	unlink(filename);
}
