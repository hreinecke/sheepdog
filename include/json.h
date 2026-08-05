#ifndef __JSON_H__
#define __JSON_H__

#include <json-c/json.h>

void node_to_json(struct sd_node *node, struct json_object *obj);
void nodes_to_json(struct sd_node *nodes, int nr_nodes, json_object *obj);

void logs_to_json(struct json_object *obj, const struct epoch_log *logs,
		  uint16_t flags);
void logs_to_json_summary(struct json_object *obj, const struct epoch_log *logs,
			  uint16_t flags);

void json_to_node(struct json_object *obj, struct sd_node *node);
void json_to_nodes(struct json_object *obj, struct sd_node *nodes,
		   int *nr_nodes);

#define JSON_ADD_STRING(o,n,v) \
	json_object_object_add((o),n,json_object_new_string((v)))
#define JSON_ADD_INT(o,n,v) \
	json_object_object_add((o),n,json_object_new_int((v)))
#define JSON_ADD_UINT64(o,n,v) \
	json_object_object_add((o),n,json_object_new_uint64((v)))
#define JSON_ADD_BOOL(o,n,v) \
	json_object_object_add((o),n,json_object_new_boolean((v)))

#endif
