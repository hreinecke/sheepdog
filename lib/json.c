/*
 * Copyright (C) 2025 Hannes Reinecke, SUSE
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sheep.h"
#include "json.h"

void node_to_json(struct sd_node *node, struct json_object *obj)
{
	const char *node_id = node_to_str(node);
#ifdef HAVE_DISKVNODES
	struct json_object *disks_obj;
	int i;
#endif

	json_object_object_add(obj, "nid",
			       json_object_new_string(node_id));
	json_object_object_add(obj, "zone",
			       json_object_new_int64(node->zone));
	json_object_object_add(obj, "space",
			       json_object_new_int64(node->space));
	json_object_object_add(obj, "nr_vnodes",
			       json_object_new_int(node->nr_vnodes));
#ifdef HAVE_DISKVNODES
	disks_obj = json_object_new_array();
	for (i = 0; i < DISK_MAX; i++) {
		struct json_object *disk_obj;
		struct disk_info *d = &node->disks[i];

		if (!d->disk_id)
			continue;
		disk_obj = json_object_new_object();
		json_object_object_add(disk_obj, "num",
				       json_object_new_int(i));
		json_object_object_add(disk_obj, "id",
				       json_object_new_int64(d->disk_id));
		json_object_object_add(disk_obj, "space",
				       json_object_new_int64(d->disk_space));
		json_object_array_add(disks_obj, disk_obj);
	}
	json_object_object_add(obj, "disks", disks_obj);
#endif
}

void nodes_to_json(struct sd_node *nodes, int nr_nodes,
		   json_object *obj)
{
	struct json_object *nodes_obj;

	if (!nodes)
		return;

	nodes_obj = json_object_new_array();
	for (int i = 0; i < nr_nodes; i++) {
		struct json_object *node_obj;

		node_obj = json_object_new_object();
		node_to_json(&nodes[i], node_obj);
		json_object_array_add(nodes_obj, node_obj);
	}
	json_object_object_add(obj, "nodes", nodes_obj);
}

#ifdef HAVE_DISKVNODES
static void json_to_disks(struct json_object *obj, struct sd_node *node)
{
	int j, nr_disks;

	nr_disks = json_object_array_length(obj);
	if (nr_disks >= DISK_MAX) {
		sd_warn("number of disks too large");
		nr_disks = DISK_MAX;
	}
	for (j = 0; j < nr_disks; j++) {
		struct json_object *disk_obj, *num_obj;
		struct json_object *id_obj, *space_obj;
		struct disk_info *disk;
		int disk_num;

		disk_obj = json_object_array_get_idx(obj, j);
		num_obj = json_object_object_get(disk_obj, "num");
		if (!num_obj)
			continue;
		disk_num = json_object_get_int(num_obj);
		disk = &node->disks[disk_num];
		id_obj = json_object_object_get(disk_obj, "id");
		if (id_obj)
			disk->disk_id = json_object_get_int64(id_obj);
		space_obj = json_object_object_get(disk_obj, "space");
		if (space_obj)
			disk->disk_space = json_object_get_int64(space_obj);
	}
}
#endif

void json_to_node(struct json_object *obj, struct sd_node *node)
{
	struct json_object_iterator itb, ite;
	const char *nid_str;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "nid")) {
			nid_str = json_object_get_string(val_obj);
			if (!str_to_node(nid_str, node)) {
				sd_warn("failed to parse '%s'", nid_str);
				return;
			}
		} else if (!strcmp(key, "nr_vnodes"))
			node->nr_vnodes = json_object_get_int(val_obj);
		else if (!strcmp(key, "zone"))
			node->zone = json_object_get_int64(val_obj);
		else if (!strcmp(key, "space"))
			node->space = json_object_get_int64(val_obj);
#ifdef HAVE_DISKVNODES
		else if (!strcmp(key, "disks"))
			json_to_disks(val_obj, node);
#endif
		else
			sd_warn("unhandled node attribute '%s'", key);
		json_object_iter_next(&itb);
	}
}

void json_to_nodes(struct json_object *obj, struct sd_node *nodes,
		   int *nr_nodes)
{
	int i, n = json_object_array_length(obj);

	for (i = 0; i < n; i++) {
		struct json_object *node_obj;
		struct sd_node *node = &nodes[i];

		node_obj = json_object_array_get_idx(obj, i);
		memset(node, 0, sizeof(*node));
		json_to_node(node_obj, node);
	}
	*nr_nodes = n;
}
