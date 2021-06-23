#include "../../include/layer3.h"
#include "../../include/hash.h"

/*void rt_hash_display(ctrl_table_t *hashTable){
   unsigned int table_size = hashTable->table_size;
   for (int i = 0; i < table_size; i++) { 
     if ((hashTable->table_ptr)[i].is_entry == 1){ 
           printf("%d. dest ip : %s \n", i, ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->dest_ip);
           printf("mask : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->mask); 
           printf("  is direct : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->is_direct == TRUE); 
           printf("  outgoing intf : %s\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->oif); 
           printf("  gateway ip : %s\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->gw_ip); 
           printf("  cost metric : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->cost_metric); 
     }
     //else
     //    printf("%d --> \n",i); 
   }  
};*/
void rt_hash_display(ctrl_table_t *hashTable){
   unsigned int table_size = hashTable->table_size;
   for (int i = 0; i < table_size; i++) { 
     if ((hashTable->table_ptr)[i].is_entry == 1){ 
           printf("%d. dest ip : %s \n", i, ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->dest_ip);
           printf("mask : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->mask); 
           printf("is direct : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->is_direct == TRUE); 
          //  for(int j=0; j <MAX_NXT_HOPS; i++) {
           for(int j=0; j < (((rt_entry_t *)(hashTable->table_ptr)[i].entry)->cur_ecmp_num); j++) {
             if(((rt_entry_t *)(hashTable->table_ptr)[i].entry)->nxt_hops[j] == NULL) {
               continue;
             }
             printf("outgoing intf : %s\n",((rt_entry_t *)(hashTable->table_ptr)[i].entry)->nxt_hops[j]->oif == NULL ? "N/A" : ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->nxt_hops[j]->oif->name);
          ;
             printf("gateway ip : %s\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->nxt_hops[j]->gw_ip); 
           }
           printf("cost metric : %d\n", ((rt_entry_t *)(hashTable->table_ptr)[i].entry)->cost_metric); 
     }
     //else
     //    printf("%d --> \n",i); 
   }  
};


void *rt_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size){
    for(int i = 0 ; i < prev_table_size; i++) {
      int cur = 0;

      if((old_table->table_ptr)[i].is_entry == 0) continue;
      rt_entry_t *n = (rt_entry_t *)((old_table->table_ptr)[i].entry);
      char *key = n->dest_ip;
      int a = preHash(cur, key, *table_size);
      cur++;

      if((new_table->table_ptr)[a].is_entry == 0) {
        (new_table->table_ptr)[a].entry = n; 
        (new_table->table_ptr)[a].is_entry = 1;
        //printf("\nreinsert %s success at %d\n", key, a);
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
};

void* rt_insert_routine(ctrl_table_t *ctr_table, rt_entry_t* entry){

  unsigned int *table_size = &(ctr_table->table_size);
  unsigned int *curr_size = &(ctr_table->curr_size);
  void *newHashTable;
  graph_elements_t **hash_graph;
  hash_graph = &(ctr_table->table_ptr);

  if(isFull(ctr_table)){
    //printf("the graph table is full, resize ... \n");
    unsigned int prev_table_size = *table_size;
    (*table_size) *=2;
    newHashTable = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
    make_hash_table(newHashTable, *table_size, ROUTER_T);

    init_hash_table(newHashTable, ROUTER_T);
    // 옮기기
    *hash_graph = reHash(ctr_table, newHashTable, prev_table_size, table_size);  
    ctr_table = newHashTable;
  }
  //concat string : 
  // how to implement longest match first
   
  char* key = entry->dest_ip;
  int cur = 0;
  int a = preHash(cur, key, *table_size);
  cur++;

  if(!(*hash_graph)[a].is_entry){
    (*hash_graph)[a].entry = entry;
    (*hash_graph)[a].is_entry = 1;
    //printf("\ninsert %s success at %d\n", key, a);
  } else {
    while(1){
      a = preHash(cur, key, *table_size);
      if(!(*hash_graph)[a].is_entry){
        (*hash_graph)[a].entry = entry;
        (*hash_graph)[a].is_entry = 1;
        //printf("\n insert %s success %d trial at %d\n", key, cur+1, a);
        break;
      }
      cur++;
    }
  }
  (*curr_size)++;  
  return entry;  
};

void *rt_search_routine(ctrl_table_t *ctr_table, char *key){
  int table_size = ctr_table->table_size;
  graph_elements_t *hash_graph = ctr_table->table_ptr;

  int trial = 0;
  int phash;
  void *found_entry;
  while(1){
    if(trial >= table_size) {
      //printf("no result\n");
      return NULL;
    }
    //mutex 등의 보호 필요 
    phash = preHash(trial, key, table_size);
    char *to_be_compared; 
    if(!(((graph_elements_t *)hash_graph)[phash].is_entry)) {
      //printf("no result with that name\n");
      return NULL;
    }
    to_be_compared = ((rt_entry_t *)(((graph_elements_t *)hash_graph)[phash].entry))->dest_ip;        
     
    if(!strncmp(to_be_compared, key, strlen(key)+1)) {
      // found_entry = hash_graph+phash;
      //printf("success, found %s\n", key);
      return ((graph_elements_t *)hash_graph)[phash].entry;
    }
    trial++;
  }  
};
