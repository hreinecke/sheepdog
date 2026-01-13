/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <json-c/json.h>
#include "sheep_priv.h"

static struct sheepdog_config config;

char *config_path, *node_config_path;

#define CONFIG_PATH "/config"

#define _SET_CINFO_VAL(o, c, n) \
	if ((c)->n) \
		json_object_object_add(o, #n,		\
			       json_object_new_int((c)->n))

static void config_to_json(struct sheepdog_config *cfg,
			   struct json_object *obj)
{
	const char *default_store = (const char *)cfg->default_store;
	struct json_object *cfg_obj;

	cfg_obj = json_object_new_object();
	json_object_object_add(cfg_obj, "ctime",
			       json_object_new_int64(cfg->ctime));
	_SET_CINFO_VAL(cfg_obj, cfg, flags);
	_SET_CINFO_VAL(cfg_obj, cfg, copies);
	if (strlen(default_store))
		json_object_object_add(cfg_obj, "default_store",
				       json_object_new_string(default_store));
	json_object_object_add(cfg_obj, "shutdown",
			       json_object_new_boolean(cfg->shutdown));
	_SET_CINFO_VAL(cfg_obj, cfg, copy_policy);
	_SET_CINFO_VAL(cfg_obj, cfg, block_size_shift);
	_SET_CINFO_VAL(cfg_obj, cfg, version);
	json_object_object_add(cfg_obj, "space",
			       json_object_new_int64(cfg->space));
	json_object_object_add(obj, "config", cfg_obj);
}

static int write_config(void)
{
	int ret;
	struct json_object *obj;
	const char *json_str;

	obj = json_object_new_object();
	config_to_json(&config, obj);
	json_str = json_object_to_json_string_ext(obj,
						  JSON_C_TO_STRING_PRETTY);
	ret = atomic_create_and_write(config_path, json_str,
				      strlen(json_str), true, false);
	json_object_put(obj);
	if (ret < 0) {
		sd_err("atomic_create_and_write() failed");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

static void check_tmp_config(void)
{
	int ret;
	char tmp_config_path[PATH_MAX];

	snprintf(tmp_config_path, PATH_MAX, "%s.tmp", config_path);

	ret = unlink(tmp_config_path);
	if (!ret || ret != ENOENT)
		return;

	sd_info("removed temporal config file");
}

static int get_cluster_config(struct cluster_info *cinfo)
{
	cinfo->ctime = config.ctime;
	cinfo->nr_copies = config.copies;
	if (config.ctime > 0)
		cinfo->flags = config.flags;
	else
		cinfo->flags = (config.flags & ~SD_CLUSTER_FLAG_AUTO_VNODES) |
			(cinfo->flags & SD_CLUSTER_FLAG_AUTO_VNODES);
	cinfo->copy_policy = config.copy_policy;
	cinfo->block_size_shift = config.block_size_shift;
	memcpy(cinfo->default_store, config.default_store,
	       sizeof(config.default_store));

	return SD_RES_SUCCESS;
}

int init_node_config_file(void)
{
	int fd, ret;
	struct stat st;

	fd = open(node_config_path, O_RDONLY);
	if (fd < 0) {
		/* this node doesn't have a node config, do nothing */
		return 0;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		close(fd);
		sd_err("failed to stat node config (%s): %m", node_config_path);
		return -1;
	}

	ret = xread(fd, &sys->ninfo, sizeof(sys->ninfo));
	if (ret != sizeof(sys->ninfo)) {
		sd_err("failed to read node config (%s): %m", node_config_path);
		return -1;
	}

	close(fd);
	return 0;
}

static int json_to_config(struct json_object *obj,
			  struct sheepdog_config *cfg)
{
	struct json_object_iterator itb, ite;
	struct json_object *cfg_obj;
	int num_val = 0;

	cfg_obj = json_object_object_get(obj, "config");
	if (!cfg_obj) {
		sd_warn("%s: invalid json payload, 'config' missing",
			__func__);
		return 0;
	}
	itb = json_object_iter_begin(cfg_obj);
	ite = json_object_iter_end(cfg_obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "ctime"))
			cfg->ctime = json_object_get_int64(val_obj);
		else if (!strcmp(key, "flags"))
			cfg->flags = json_object_get_int(val_obj);
		else if (!strcmp(key, "copies"))
			cfg->copies = json_object_get_int(val_obj);
		else if (!strcmp(key, "default_store")) {
			strcpy((char *)cfg->default_store,
			       json_object_get_string(val_obj));
		} else if (!strcmp(key, "shutdown"))
			cfg->shutdown = json_object_get_boolean(val_obj);
		else if (!strcmp(key, "copy_policy"))
			cfg->copy_policy = json_object_get_int(val_obj);
		else if (!strcmp(key, "block_size_shift"))
			cfg->block_size_shift = json_object_get_int(val_obj);
		else if (!strcmp(key, "version"))
			cfg->version = json_object_get_int(val_obj);
		else if (!strcmp(key, "space"))
			cfg->space = json_object_get_int64(val_obj);
		else {
			sd_warn("%s: unhandled key '%s'", __func__, key);
			num_val--;
		}
		num_val++;
		json_object_iter_next(&itb);
	}
	return num_val;
}

int init_config_file(void)
{
	int fd, ret = 0;
	struct stat st;
	char *cfg_file = NULL;
	struct json_object *obj;
	bool is_json_config = false;

	check_tmp_config();

	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			sd_err("failed to read config file, %m");
			return -1;
		}
		goto create;
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		sd_err("failed to stat config file, %m");
		close(fd);
		return -1;
	}
	cfg_file = xzalloc(st.st_size + 1);
	ret = xread(fd, cfg_file, st.st_size);
	if (ret == 0) {
		goto create;
	}
	if (ret < 0) {
		sd_err("failed to read config file, %m");
		goto out;
	}

	obj = json_tokener_parse(cfg_file);
	if (!obj) {
		sd_info("reading from binary config file");
		memcpy(&config, cfg_file, sizeof(config));
	} else {
		sd_info("reading from json config file");
		json_to_config(obj, &config);
		json_object_put(obj);
		is_json_config = true;
	}

	if (!is_json_config && config.version != SD_FORMAT_VERSION) {
		sd_err("This sheep version is not compatible with"
		       " the existing data layout, %d", config.version);
		if (sys->upgrade) {
			/* upgrade sheep store */
			ret = sd_migrate_store(config.version, SD_FORMAT_VERSION);
			if (ret == 0) {
				/* reload config file */
				ret = xpread(fd, cfg_file, st.st_size, 0);
				if (ret != st.st_size) {
					sd_err("failed to reload config file,"
					       " %m");
					ret = -1;
				} else {
					obj = json_tokener_parse(cfg_file);
					if (!obj) {
						sd_err("failed to re-parse config file");
						ret = -1;
					} else {
						json_to_config(obj, &config);
						json_object_put(obj);
						ret = 0;
					}
					goto reload;
				}
			}
			goto out;
		}

		sd_err("use '-u' option to upgrade sheep store");
		ret = -1;
		goto out;
	}

reload:
	if ((config.flags & SD_CLUSTER_FLAG_AUTO_VNODES) !=
	    (sys->cinfo.flags & SD_CLUSTER_FLAG_AUTO_VNODES)
		&& !sys->gateway_only
		&& config.ctime > 0) {
		sd_err("Designation of before a restart and a vnodes option is different.");
		return -1;
	}

	ret = 0;
	get_cluster_config(&sys->cinfo);
	if ((config.flags & SD_CLUSTER_FLAG_DISKMODE) !=
	    (sys->cinfo.flags & SD_CLUSTER_FLAG_DISKMODE)) {
		sd_err("This sheep can't run because "
		       "exists data format mismatch");
		return -1;
	}

create:
	config.version = SD_FORMAT_VERSION;
	if (write_config() != SD_RES_SUCCESS)
		ret = -1;

out:
	if (cfg_file)
		free(cfg_file);
	close(fd);

	return ret;
}

void init_config_path(const char *base_path)
{
	int len = strlen(base_path) + strlen(CONFIG_PATH) + 1;

	config_path = xzalloc(len);
	snprintf(config_path, len, "%s" CONFIG_PATH, base_path);

	len = strlen(base_path) + strlen(NODE_CONFIG_PATH) + 1;
	node_config_path = xzalloc(len);
	snprintf(node_config_path, len, "%s" NODE_CONFIG_PATH, base_path);
}

int set_cluster_config(const struct cluster_info *cinfo)
{
	config.ctime = cinfo->ctime;
	config.copies = cinfo->nr_copies;
	config.copy_policy = cinfo->copy_policy;
	config.flags = cinfo->flags;
	config.block_size_shift = cinfo->block_size_shift;
	memset(config.default_store, 0, sizeof(config.default_store));
	pstrcpy((char *)config.default_store, sizeof(config.default_store),
		(char *)cinfo->default_store);

	return write_config();
}

int set_node_space(uint64_t space)
{
	config.space = space;

	return write_config();
}

int get_node_space(uint64_t *space)
{
	*space = config.space;

	return SD_RES_SUCCESS;
}

bool is_cluster_formatted(void)
{
	struct cluster_info cinfo;

	get_cluster_config(&cinfo);

	return cinfo.ctime != 0;
}

int set_cluster_shutdown(bool down)
{
	config.shutdown = down;
	return write_config();
}

bool was_cluster_shutdowned(void)
{
	return config.shutdown;
}

static inline __attribute__((used)) void __sd_config_format_build_bug_ons(void)
{
	/* never called, only for checking BUILD_BUG_ON()s */
	BUILD_BUG_ON(sizeof(struct sheepdog_config) != SD_CONFIG_SIZE);
}
