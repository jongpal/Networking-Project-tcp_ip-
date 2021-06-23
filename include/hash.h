#ifndef __HASH__
#define __HASH__
// #include "graph.h"

#include "layer2.h"

// enum type {
//   GRAPH_T, //graph_elements_t -> graph_t
//   ARP_T, //arp_table_t -> ctrl_arp_table_t
//   MAC_T, //mac table
//   NODE_T, //node_t
//   ROUTER_T, 
// };

// typedef struct graph_elements_{
//   char is_entry;
//   // node_t *entry;
//   // enum type table_type;
//   void *entry;
// } graph_elements_t;

// typedef struct table_generic_controller {
//   char topology_name[32];
//   unsigned int table_size;
//   unsigned int curr_size;
//   // union {
//   //   arp_table_t *arp_table;
//   //   mac_table_t *mac_table;
//   //   graph_elements_t *hash_graph;
//   // };
//   enum type table_type;
//   graph_elements_t *table_ptr;
// } ctrl_table_t;


// void init_hash_table(void *table ,enum type t);
void init_hash_table(ctrl_table_t *table ,enum type t);

// void make_hash_table (graph_elements_t **ht);
// void make_hash_table (void *table, unsigned int table_size ,enum type t);
void make_hash_table (ctrl_table_t *table, unsigned int table_size ,enum type t);

int h1(int k, unsigned int table_size);
int h2(int k, unsigned int table_size);
// int get_graph_size();
// int get_table_size();
int preHash (int i, char* k, unsigned int table_size);
// char isFull(void *ctrl_table, enum type t);
char isFull(ctrl_table_t *ctrl_table);
// void displayTable(graph_elements_t * hashTable);
void displayTable(ctrl_table_t * hashTable, enum type t);
// void displayTable(void * hashTable, enum type t);
void* reHash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size);
// graph_elements_t* reHash(graph_elements_t **old_graph, graph_elements_t **new_graph, int prev_table_size);
void* insert(ctrl_table_t *ctr_table, void *node);
// node_t* insert(graph_elements_t **hash_graph, node_t *node);
// void *search(void* hash_graph, unsigned int table_size, char *key, enum type t);
void *search(ctrl_table_t* ctr_table, char *key);
// node_t *search(graph_elements_t* hash_graph, char *node_name);
bool_t deletion(ctrl_table_t* ctrl_table, char *key);
// char* deletion(graph_elements_t* hash_graph, char *node_name);
#endif