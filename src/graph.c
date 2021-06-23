// #include "graph.h"
#include "../include/hash.h"
#include "../include/communication.h"

extern void init_arp_table(node_t *node);
extern void init_mac_table(node_t *node);
ctrl_table_t *create_new_graph(char *graph_name){
  ctrl_table_t *new_graph = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
  strncpy(new_graph->topology_name, graph_name, strlen(graph_name));
  new_graph->topology_name[strlen(graph_name)] = '\0';

  // make_hash_table(&new_graph->hash_graph);
  make_hash_table((void *)new_graph, 2, NODE_T);
  // init_hash_table(&new_graph->hash_graph);
  init_hash_table(new_graph, NODE_T);
  return new_graph;
}

node_t *create_graph_node(ctrl_table_t* graph, char *node_name) {
  
  node_t *new_node = (node_t *)calloc(1, sizeof(node_t));
  strncpy(new_node->name,node_name, strlen(node_name));
  init_node_nw_props(new_node);
  // init_arp_table(new_node);
  // init_mac_table(new_node);
  // config_node_udp_props(new_node);
  // initialize if_list ; after dynamic allocation
  // memset(new_node->if_list, -1, sizeof(new_node->if_list));

//graph->hash_graph 를 변경하려고 하는 것인데, 그냥 graph->hash_graph 만 넘겨주면 그냥 주소 값만 복사하여 주는 것이고 ('복사' 가 중요) 이 거 자체는 변경 못한다. 따라서 뭘 변경하려고 할때는 그것의 주소값을 넘겨주고 그것의 포인터로 접근해서 변경해야한다.
  // insert((void **)&graph->hash_graph, new_node, G_E_T);
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
    // if((int)(node->if_list[i]->name) == -1) {
    //   available_slot_ind = i;
    //   break;
    // }
    //assuming interface itselt won't be deleted
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
  // node_t* found_node = search(topo->hash_graph, node_name);
  node_t* found_node = search(topo, node_name);
  // printf("node ofund : %s\n", found_node->name);
  // printf("node ofund : %d\n", topo->table_ptr-);
  return found_node;
}