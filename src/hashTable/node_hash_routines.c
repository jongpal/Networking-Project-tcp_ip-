#include "../../include/layer2.h"
#include "../../include/hash.h"

void* node_insert_routine(ctrl_table_t *ctr_table, node_t *node) {
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
    make_hash_table(newHashTable, *table_size, NODE_T);

    init_hash_table(newHashTable, NODE_T);
    // 옮기기
    *hash_graph = reHash(ctr_table, newHashTable, prev_table_size, table_size);  
    ctr_table = newHashTable;
  }
  char* key = node->name;
  int cur = 0;
  int a = preHash(cur, key, *table_size);
  cur++;

  if(!(*hash_graph)[a].is_entry){
    (*hash_graph)[a].entry = node;
    (*hash_graph)[a].is_entry = 1;
    //printf("\ninsert %s success at %d\n", key, a);
  } else {
    while(1){
      a = preHash(cur, key, *table_size);
      if(!(*hash_graph)[a].is_entry){
        (*hash_graph)[a].entry = node;
        (*hash_graph)[a].is_entry = 1;
        //printf("\n insert %s success %d trial at %d\n", key, cur+1, a);
        break;
      }
      cur++;
    }
  }
  (*curr_size)++;  
  return node;
}
void *node_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size){
    for(int i = 0 ; i < prev_table_size; i++) {
      int cur = 0;

      if((old_table->table_ptr)[i].is_entry == 0) continue;
      node_t *n = (node_t *)((old_table->table_ptr)[i].entry);
      char *key = n->name;
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

void *node_search_routine(ctrl_table_t *ctr_table, char *key) {
  int table_size = ctr_table->table_size;
  graph_elements_t *hash_graph = ctr_table->table_ptr;

  int trial = 0;
  int phash;
  void *found_entry;
  while(1){
    if(trial >= table_size) {
      //printf("no result \n");
      return NULL;
    }
    //mutex 등의 보호 필요 
    phash = preHash(trial, key, table_size);
    // printf("phsh : %d\n", phash);
    graph_elements_t *to_be_compared; 
    if(!(((graph_elements_t *)hash_graph)[phash].is_entry)){
      //printf("no result with the name %s\n", key);
      return NULL;
    } 
    // to_be_compared = ((node_t *)(((graph_elements_t *)hash_graph)[phash].entry))->name;        
    to_be_compared = ((graph_elements_t *)hash_graph)+phash;        

    // if(!strncmp(to_be_compared, "-1", strlen("-1"))) {
    //   printf("no result with the name %s\n", key);
    //   return NULL;
    // }          
    if(!strncmp(((node_t *)to_be_compared->entry)->name, key, strlen(key)+1)) {
      // found_entry = hash_graph+phash;
      //printf("success, found %s\n", key);
      return ((graph_elements_t *)hash_graph)[phash].entry;
    }
    trial++;
  }
}
// void node_hash_init(ctrl_table_t *table){
//   unsigned int table_size = table->table_size;
//   for(int i = 0 ; i < table_size;i++){
//     (table->table_pt)[i].is_entry = 0;
//   }  
// };

// void node_hash_create(ctrl_table_t *table, unsigned int table_size){
//   table->hash_graph = (graph_elements_t *)calloc(1, sizeof(graph_elements_t)*table_size);
//   table->table_size = table_size;
//   table->curr_size = 0;
// }

// void node_hash_display(ctrl_table_t *hashTable){
//   unsigned int table_size = hashTable->table_size;
//   for (int i = 0; i < table_size; i++) { 
//     if ((hashTable->hash_graph)[i].is_entry == 1) 
//           printf("%d --> %s \n", i, (hashTable->hash_graph)[i].entry->name); 
//     else
//         printf("%d --> \n",i); 
//   }   
// }

