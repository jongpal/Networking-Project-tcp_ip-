// #include "graph.h"
#include "../include/hash.h"
#include "../include/communication.h"

extern void init_arp_table(node_t *node);
extern void init_mac_table(node_t *node);
ctrl_table_t *create_new_graph(char *graph_name){
  ctrl_table_t *new_graph = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
  strncpy(new_graph->topology_name, graph_name, strlen(graph_name));
  new_graph->topology_name[strlen(graph_name)] = '\0';

  make_hash_table((void *)new_graph, 2, NODE_T);
  init_hash_table(new_graph, NODE_T);
  return new_graph;
}

node_t *create_graph_node(ctrl_table_t* graph, char *node_name) {
  
  node_t *new_node = (node_t *)calloc(1, sizeof(node_t));
  strncpy(new_node->name,node_name, strlen(node_name));
  init_node_nw_props(new_node);

  insert(graph, new_node);
  return new_node;
}

// node_t *create_home_agent_node(ctrl_table_t *graph, char *node_name) {
//   node_t *new_node = (node_t *)calloc(1, sizeof(node_t));
//   strncpy(new_node->name,node_name, strlen(node_name));
//   init_node_nw_props(new_node);

//   new_node->node_nw_props.is_home_agent = TRUE;
  
// }

interface_t* get_nbr_node_intf(interface_t *interface){
  if(!interface->link) return NULL;
  interface_t *rif = strcmp(interface->link->if1.name,interface->name) == 0 ? &(interface->link->if2) : &(interface->link->if1);
  return rif;
}


int get_node_intf_available_slot(node_t *node){
  int available_slot_ind = -1;
  for(int i = 0; i < MAX_INTF_PER_NODE; i++) {
    if(!node->if_list[i]){
      available_slot_ind = i;
      break;
    }
  }

  return available_slot_ind;
} 

void insert_link(node_t *from_node, node_t *to_node, char *from_if, char *to_if, unsigned int cost){
  link_t *link = (link_t *)calloc(1, sizeof(link_t));
  
  strncpy(link->if1.name, from_if, strlen(from_if)+1);
  strncpy(link->if2.name, to_if, strlen(to_if)+1);
  link->if1.node = from_node;
  link->if2.node = to_node;
  link->if1.link = link;
  link->if2.link = link;
  link->cost = cost;

  int ind = get_node_intf_available_slot(from_node);
  from_node->if_list[ind] = &link->if1;
  ind = get_node_intf_available_slot(to_node);
  to_node->if_list[ind] = &link->if2;

  init_intf_nw_props(&link->if1.intf_nw_props);
  init_intf_nw_props(&link->if2.intf_nw_props);

  interface_assign_mac_address(&link->if1);
  interface_assign_mac_address(&link->if2);
}

interface_t *
get_node_if_by_name(node_t *node, char *if_name){
  interface_t *found_if = NULL;
  int until = get_node_intf_available_slot(node);
  int i;
  for(i = 0 ; i < until; i++){
    if(!strncmp(node->if_list[i]->name, if_name, strlen(if_name))) {
      found_if = node->if_list[i];
      break;
    }
  }
  return found_if;
}

node_t *
get_node_by_node_name(ctrl_table_t *topo, char *node_name){
  node_t* found_node = search(topo, node_name);
  return found_node;
}
