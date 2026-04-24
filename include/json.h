#ifndef __JSON_H__
#define __JSON_H__

#include <json-c/json.h>

void node_to_json(struct sd_node *node, struct json_object *obj);
void nodes_to_json(struct sd_node *nodes, int nr_nodes, json_object *obj);

void logs_to_json(struct json_object *obj, const struct epoch_log *logs,
		  uint16_t flags);

void json_to_node(struct json_object *obj, struct sd_node *node);
void json_to_nodes(struct json_object *obj, struct sd_node *nodes,
		   int *nr_nodes);

#endif
