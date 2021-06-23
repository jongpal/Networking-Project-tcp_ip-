#include "../../include/hash.h"
#include "../../include/layer2.h"
#include "../../include/layer3.h"

extern void free_arp_table(node_t *node);
extern void put_uchar_mac_into_char(unsigned char* mac, char *charred_mac);

extern void *node_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size);
extern void *arp_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size);
extern void *mac_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size);
extern void *rt_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size);

extern void* node_insert_routine(ctrl_table_t *ctr_table, node_t *node);
extern void* arp_insert_routine(ctrl_table_t *ctr_table, arp_entries_t *arp);
extern void* mac_insert_routine(ctrl_table_t *ctr_table, mac_entry_t *mac);
extern void* rt_insert_routine(ctrl_table_t *ctr_table, rt_entry_t* entry);

extern void *node_search_routine(ctrl_table_t *ctr_table, char *key);
extern void *arp_search_routine(ctrl_table_t *ctr_table, char *key);
extern void *mac_search_routine(ctrl_table_t *ctr_table, char *key);
extern void *rt_search_routine(ctrl_table_t *ctr_table, char *key);

extern void rt_hash_display(ctrl_table_t *hashTable);

void init_hash_table(ctrl_table_t *table, enum type t){
  unsigned int table_size = table->table_size;
  for(int i = 0 ; i < table_size;i++){
    (table->table_ptr)[i].is_entry = 0;
  }    
  table->table_type = t;
}

void make_hash_table (ctrl_table_t *table, unsigned int table_size , enum type t){
  //default table size. : start from 2
  table->table_ptr = (graph_elements_t *)calloc(1, sizeof(graph_elements_t)*table_size);
  table->table_size = table_size;
  table->curr_size = 0;
  table->table_type = t;
}

int h1(int k, unsigned int table_size){
  return k % table_size;
}

int h2(int k, unsigned int table_size) {
  int ret = 1 + k % (table_size - 1);
  if(ret % 2 == 0) ret -=1;
  return ret;
}

int preHash (int i, char* k, unsigned int table_size) {
  int ktoint = 0;
  for(int j = 0 ; j < strlen(k); j ++){
    ktoint += (int)k[j];
  }
  return (h1(ktoint, table_size) + i*h2(ktoint, table_size)) % table_size;
}
char isFull(ctrl_table_t *ctrl_table) {
  int curr_size, table_size;
  curr_size = ctrl_table->curr_size;
  table_size = ctrl_table->table_size;
  return (3*curr_size) >= (2*table_size) ? 1 : 0;
}

void displayTable(ctrl_table_t* hashTable, enum type t){
  unsigned int table_size;
  switch(t){
    // case NODE_T:
    //   node_hash_display(hashTable);
    //   break;
    // case ARP_T:
    //   arp_hash_display(hashTable);
    //   break;
    // case MAC_T:
    //   mac_hash_display(hashTable);
    //   break;
    case ROUTER_T:
      rt_hash_display(hashTable);
    default: break;
  }
}

void* reHash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size) {
  enum type t = old_table->table_type;
  switch(t){
    case NODE_T:
      return node_rehash(old_table, new_table, prev_table_size, table_size);
    case ARP_T:
      return arp_rehash(old_table, new_table, prev_table_size, table_size);
    case MAC_T:
      return mac_rehash(old_table, new_table, prev_table_size, table_size);
    case ROUTER_T:
      return rt_rehash(old_table, new_table, prev_table_size, table_size);
    default : return NULL;
  }
  // free(((graph_t *)(old_table))->hash_graph);
  // return ((graph_t *)(new_table))->hash_graph;
}


void* insert(ctrl_table_t *ctr_table, void *entry){

  enum type t = ctr_table->table_type;
  switch(t) {
    case NODE_T: 
      entry = node_insert_routine(ctr_table, (node_t *)entry);
      break;
    case ARP_T:
      entry = arp_insert_routine(ctr_table, (arp_entries_t *)entry);
      break;
    case MAC_T: 
      entry = mac_insert_routine(ctr_table, (mac_entry_t *)entry);  
      break;
    case ROUTER_T:
      entry = rt_insert_routine(ctr_table, (rt_entry_t*)entry);
      break;
    default: 
      break;
  }
  return entry;
}

//key : name for node, ip_addr for arp
void *search(ctrl_table_t* ctr_table, char *key) {
  unsigned int table_size = ctr_table->table_size;
  enum type t = ctr_table->table_type;
  switch(t) {
    case NODE_T: {
      return node_search_routine(ctr_table, key);
    }
    case ARP_T:{
      return arp_search_routine(ctr_table, key);
    }
    case MAC_T:{
      return mac_search_routine(ctr_table, key);
    }
    case ROUTER_T:{
      return rt_search_routine(ctr_table, key);
    }
    default:{
      return NULL;
    }
  }
  return NULL;
}

//key : name for node , ipaddr for arp
bool_t deletion(ctrl_table_t* ctrl_table, char *key) {
  enum type t = ctrl_table->table_type;

  int trial = 0;
  int phash;
  char *is_entry;
  char *to_be_compared;
  unsigned int table_size;
  char mac[13];

  while(1){
    unsigned int table_size;
    unsigned int *curr_size;
    table_size = (ctrl_table)->table_size;
    phash = preHash(trial, key, table_size);
    curr_size = &((ctrl_table)->curr_size);
    is_entry = &(((ctrl_table)->table_ptr)[phash].is_entry);
    switch(t){
      case NODE_T:
        to_be_compared = ((node_t *)(((ctrl_table)->table_ptr)[phash].entry)) ->name;
        break;
      case ARP_T:
        to_be_compared = ((arp_entries_t *)((ctrl_table->table_ptr)[phash].entry))-> ip_addr.ip_addr;
        break;
      case MAC_T:
        put_uchar_mac_into_char(((mac_entry_t *)((ctrl_table->table_ptr)[phash].entry))->mac_addr.mac_addr, mac);
        to_be_compared = mac;
        break;
      default: break;
    }
    if(!(*is_entry)) {
      printf("no node with that name\n");
      return FALSE;
    } else if(!strncmp(to_be_compared, key, strlen(key))){

    *is_entry = 0;
    (*curr_size)--;
    
    printf("deletion complete !\n");
    free((ctrl_table->table_ptr)[phash].entry);
  
    // free(hash_graph[phash].node);
    return TRUE;
    }
    trial++;
  }
}
