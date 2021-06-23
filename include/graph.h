#ifndef __GRAPH_H__
#define __GRAPH_H__
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <memory.h>
#include "net.h"
#define IF_NAME_SIZE 30
#define NODE_NAME_SIZE 30
#define MAX_INTF_PER_NODE 10

typedef struct node_ node_t;
// struct arp_table_t;
typedef struct link_ link_t;
typedef struct spf_result_ spf_result_t;
typedef struct spf_data spf_data_t;

typedef struct interface_{
  char name[IF_NAME_SIZE];
  node_t* node;
  link_t* link;
  intf_nw_props_t intf_nw_props;
}interface_t;

typedef struct node_{
  char name[NODE_NAME_SIZE];
  interface_t* if_list[MAX_INTF_PER_NODE];
  int udp_sock_fd;
  unsigned int udp_port_no;
  spf_data_t *spf_data;
  // ctrl_arp_table_t *ctr_arp_table;
  node_nw_props_t node_nw_props;
}node_t;

typedef struct link_{
  interface_t if1;
  interface_t if2;
  unsigned int cost;
}link_t;

enum type {
  GRAPH_T, //graph_elements_t -> graph_t
  ARP_T, //arp_table_t -> ctrl_arp_table_t
  MAC_T, //mac table
  NODE_T, //node_t
  ROUTER_T, 
};

typedef struct graph_elements_{
  char is_entry;
  // node_t *entry;
  // enum type table_type;
  void *entry;
} graph_elements_t;

typedef struct table_generic_controller {
  char topology_name[32];
  unsigned int table_size;
  unsigned int curr_size;
  // union {
  //   arp_table_t *arp_table;
  //   mac_table_t *mac_table;
  //   graph_elements_t *hash_graph;
  // };
  enum type table_type;
  graph_elements_t *table_ptr;
} ctrl_table_t;



// typedef struct graph_elements_{
//   char is_entry;
//   // node_t *entry;
//   enum type_ table_type;
//   void *entry;
// } graph_elements_t;

// typedef struct graph_{
//   char topology_name[32];
//   unsigned int table_size;
//   unsigned int curr_size;
//   graph_elements_t *hash_graph;
// }graph_t;


void insert_link(node_t *from_node, node_t *to_node, char *from_if, char *to_if, unsigned int cost);
int get_node_intf_available_slot(node_t *node);
interface_t* get_nbr_node_intf(interface_t *interface);
node_t *create_graph_node(ctrl_table_t* graph, char *node_name);
ctrl_table_t *create_new_graph(char *graph_name);
interface_t *
get_node_if_by_name(node_t *node, char *if_name);
node_t *
get_node_by_node_name(ctrl_table_t *topo, char *node_name);

#endif
