#include "../../include/layer2.h"
#include "../../include/hash.h"

void* arp_insert_routine(ctrl_table_t *ctr_table, arp_entries_t *entry){
  unsigned int *table_size = &(ctr_table->table_size);
  unsigned int *curr_size = &(ctr_table->curr_size);
  void *newHashTable; 
     // arp_table_t **arp_table;
  graph_elements_t **arp_table;
  arp_table = &(ctr_table->table_ptr);

  if(isFull(ctr_table)){
    //printf("the graph table is full, resize ... \n");
    unsigned int prev_table_size = *table_size;
    (*table_size) *=2;
      
    newHashTable = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
    make_hash_table(newHashTable, *table_size, ARP_T);
    // displayTable(ctr_table, G_E_T);
    init_hash_table(newHashTable, ARP_T);
    
    // 옮기기
    *arp_table = reHash(ctr_table, newHashTable, prev_table_size, table_size);  
    ctr_table = newHashTable;
  }
  char* key = entry->ip_addr.ip_addr;
  //insert 할 놈은 mac이 하나
  unsigned char* mac = entry->mac_addr.mac_addr;
  
  int cur = 0;
  int a;
  a = preHash(cur, key, *table_size);

  if(!((*arp_table)[a].is_entry)){
    (*arp_table)[a].entry = entry;
    (*arp_table)[a].is_entry = 1;
    //printf("\n insert %s success %d trial at %d\n", key, cur+1,a);
  } 
  else if(!strncmp(key, ((arp_entries_t *)(*arp_table)[a].entry)->ip_addr.ip_addr, strlen(key)+1)) {
      if(!memcmp(((arp_entries_t *)(*arp_table)[a].entry)->mac_addr.mac_addr, mac, 6)) {
        return NULL;
      }
      (*arp_table)[a].entry = (arp_entries_t *)entry;
      (*arp_table)[a].is_entry = 1;
      //if same , not adding it, rather overwrite it
      
      return entry;
  } 
  else {
    while(1){
      a = preHash(cur, key, *table_size);
      if(!(*arp_table)[a].is_entry){
        (*arp_table)[a].entry = entry;
        (*arp_table)[a].is_entry = 1;
        //printf("\n insert %s success %d trial at %d\n", key, cur+1, a);
        break;
      }
      cur++;
    }
  }  
  (*curr_size)++;    
  return entry;
}

void* arp_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size){

  for(int i = 0 ; i < prev_table_size; i++) {
    if((old_table->table_ptr)[i].is_entry == 0) continue;
    arp_entries_t *n =  (arp_entries_t *)(old_table->table_ptr)[i].entry;
    int cur = 0;
    
    char *key = n->ip_addr.ip_addr;
      
    int a = preHash(cur, key, *table_size);

    if(!(new_table->table_ptr)[a].is_entry) {
      (new_table->table_ptr)[a].entry = n;
      (new_table->table_ptr)[a].is_entry = 1;
      //printf("\nreinsert %s success %d trial at %d\n", key, cur+1, a);
    } else {
        while(1){
          a = preHash(cur, key, *table_size);
          if(!(new_table->table_ptr)[a].is_entry) {
            (new_table->table_ptr)[a].entry = n;
            (new_table->table_ptr)[a].is_entry = 1;
            //printf("\nreinsert %s success %d trial\n", key, cur+1);
            break;
          }
          cur++;
        }     
      }
  (new_table->curr_size)++;
  }    
    
  free(old_table->table_ptr);
  return new_table->table_ptr;
}

void *arp_search_routine(ctrl_table_t *ctr_table, char *key) {
  int table_size = ctr_table->table_size;
  graph_elements_t *hash_graph = ctr_table->table_ptr;

  int trial = 0;
  int phash;
  void *found_entry;
  while(1){
    if(trial >= table_size) return NULL;
    //mutex 등의 보호 필요 
    phash = preHash(trial, key, table_size);
    // printf("phsh : %d\n", phash);
    char *to_be_compared; 
    if(!(((graph_elements_t *)hash_graph)[phash].is_entry)) return NULL;
    to_be_compared = ((arp_entries_t *)((graph_elements_t *)hash_graph)[phash].entry)->ip_addr.ip_addr;
    if(to_be_compared == NULL) {
      return NULL;
    }    

    if(!strncmp(to_be_compared, "-1", strlen("-1"))) {
      //printf("no result with the name %s\n", key);
      return NULL;
    }      
    if(!strncmp(to_be_compared, key, strlen(key)+1)) {
      // found_entry = hash_graph+phash;
      //printf("success, found %s\n", key);
      return ((graph_elements_t *)hash_graph)[phash].entry;
    }
    trial++;
  }
}
/*
void arp_hash_init(ctrl_table_t *table){
  unsigned int table_size = (table)->table_size;
  for(int i = 0 ; i < table_size;i++){
    (table->arp_table)[i].is_entry = 0;
  }  
}

void arp_hash_create(ctrl_table_t *table, unsigned int table_size){
  table->arp_table = (arp_table_t *)calloc(1,sizeof(arp_table_t)*table_size);
  table->table_size = table_size;
  table->curr_size = 0;  
}

void arp_hash_display(ctrl_table_t *hashTable) {
  unsigned int table_size = hashTable->table_size;
  for (int i = 0; i < table_size; i++) { 
    if ((hashTable->arp_table)[i].is_entry) 
          printf("%d --> %s\n", i, (hashTable->arp_table)[i].entry->oif_name); 
    else
        printf("%d --> \n",i); 
  } 
}*/
