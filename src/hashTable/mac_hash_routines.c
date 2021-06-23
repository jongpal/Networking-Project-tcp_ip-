#include "../../include/layer2.h"
#include "../../include/hash.h"


void *mac_insert_routine(ctrl_table_t *ctr_table, mac_entry_t *entry){
  unsigned int *table_size = &(ctr_table->table_size);
  unsigned int *curr_size = &(ctr_table->curr_size);
  void *newHashTable;
  graph_elements_t **mac_table;
  mac_table = &(ctr_table->table_ptr);

  if(isFull(ctr_table)){
    //printf("the graph table is full, resize ... \n");
    unsigned int prev_table_size = *table_size;
    (*table_size) *=2;
    newHashTable = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
    make_hash_table(newHashTable, *table_size, MAC_T);

    init_hash_table(newHashTable, MAC_T);
    // 옮기기
    *mac_table = reHash(ctr_table, newHashTable, prev_table_size, table_size);  
    ctr_table = newHashTable;
  }
  char key [13];
  put_uchar_mac_into_char(((mac_entry_t *)entry)->mac_addr.mac_addr, key);

  int cur = 0;
  int a = preHash(cur, key, *table_size);
  cur++;

  if(!(*mac_table)[a].is_entry){
    (*mac_table)[a].entry = entry;
    (*mac_table)[a].is_entry = 1;
    //printf("\n insert %s success at %d\n", key, a);

  } else {
    while(1){
      a = preHash(cur, key, *table_size);
      if(!(*mac_table)[a].is_entry){
        (*mac_table)[a].entry = entry;
        (*mac_table)[a].is_entry = 1;
        //printf("\n insert %s success %d trial at %d\n", key, cur+1, a);
        break;
      }
      cur++;
    }
  }
  (*curr_size)++;
  return entry;
}
void *mac_rehash(ctrl_table_t *old_table, ctrl_table_t *new_table, unsigned int prev_table_size, unsigned int *table_size){
  for(int i = 0 ; i < prev_table_size; i++) {
    int cur = 0;

    if((old_table->table_ptr)[i].is_entry == 0) continue;
    mac_entry_t *n = (old_table->table_ptr)[i].entry;
    char key [13];
    snprintf(key, 13, "%x%x%x%x%x%x", n->mac_addr.mac_addr[0], n->mac_addr.mac_addr[1], n->mac_addr.mac_addr[2], n->mac_addr.mac_addr[3], n->mac_addr.mac_addr[4], n->mac_addr.mac_addr[5]);

    int a = preHash(cur, key, *table_size);
    cur++;

    if((new_table->table_ptr)[i].is_entry == 0) {
      (new_table->table_ptr)[a].entry = n; 
      (new_table->table_ptr)[a].is_entry = 1;
      //printf("\nreinsert %s success at %d\n", key, a);
    } else {
      while(1){
        a = preHash(cur, key, *table_size);
        if(!(new_table->table_ptr)[a].is_entry) {
          (new_table->table_ptr)[a].entry = n;
          (new_table->table_ptr)[a].is_entry = 1;
        //  printf("\nreinsert %s success %d trial\n", key, cur+1);
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


void *mac_search_routine(ctrl_table_t *ctr_table, char *key) {
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
    char mac[13];
    // snprintf 에서 이렇게 바꿈
    put_uchar_mac_into_char(((mac_entry_t *)(((graph_elements_t*)hash_graph)[phash].entry))->mac_addr.mac_addr, mac);
    to_be_compared = mac;

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
void mac_hash_init(ctrl_table_t *table){
  unsigned int table_size = table->table_size;
  for(int i = 0; i< table_size; i++){
    (table->mac_table)[i].is_entry = 0;
  }
}

void mac_hash_create(ctrl_table_t *table, unsigned int table_size){
  table->mac_table = (mac_table_t *)calloc(1, sizeof(mac_table_t)*table_size);
  table->table_size = table_size;
  table->curr_size = 0;
}

void mac_hash_display(ctrl_table_t *hashTable) {
  unsigned int table_size = hashTable->table_size;
  for (int i = 0 ; i <table_size; i++) {
    if((hashTable->mac_table)[i].is_entry){
        for(int i = 0 ; i < MAC_LENGTH; i++) {
        if(i != 0) printf(":");
        printf("%x", hashTable->mac_table->entry->mac_addr.mac_addr[i]);
        }
        printf("--> %s\n", hashTable->mac_table->entry->oif_name);
    }
    else printf("%d --> \n", i);
  }
}*/
