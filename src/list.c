#include "./../include/list.h"
#include "./../include/tcp_public.h"


extern int spf_compare_fn(void *data1, void *data2);
//all data should be previously allocated

void add_list_front(list_ht *ht, list_link_t *entry) {
  //if head is NULL : set this entry to head&&tail
  if(ht->head->next == NULL) {
    ht->head->next = entry;
    ht->tail->prev = entry;
    ht->head->prev = NULL;
    ht->head->next = NULL;

    entry->prev = ht->head;
    entry->next = ht->tail;
    return;
  }
  //add it front
  list_link_t *prev_first= ht->head->next;
  entry->next = prev_first;
  prev_first->prev = entry;
  ht->head->next = entry;
  entry->prev = ht->head;
  return;
} 

void add_list_back(list_ht *ht, list_link_t *entry){
  if(ht->head->next == ht->tail) {
    ht->head->next = entry;
    ht->tail->prev = entry;
    entry->prev = ht->head;
    entry->next = ht->tail;
    return;
  }
  //add it back
  list_link_t *prev_last = ht->tail->prev;
  prev_last->next = entry;
  entry->prev = prev_last;
  ht->tail->prev = entry;
  entry->next = ht->tail;
  return;
};

list_link_t* pop_list_front(list_ht *ht){
  // if(ht->head == NULL || ht->tail == NULL) return NULL;
  if(ht->head->next == ht->tail) return NULL;
  list_link_t *prev_first = ht->head->next;
  list_link_t *new_first = prev_first->next;
  new_first->prev = ht->head;
  ht->head->next = new_first;
  // free(prev_head);
  return prev_first;
};
list_link_t* pop_list_back(list_ht *ht){
  if(ht->head == NULL || ht->tail == NULL) return NULL;
  list_link_t *prev_last = ht->tail->prev;
  list_link_t *new_last = prev_last->prev;
  new_last->next = ht->tail;
  ht->tail->prev = new_last;
  // free(prev_tail);
  return prev_last;
}
void remove_list(list_link_t *entry){
  if(entry->prev == NULL || entry->next == NULL) return;

  entry->prev->next = entry->next;
  entry->next->prev = entry->prev;
  // free ?? 
  entry->next = NULL;
  entry->prev = NULL;
  // free(entry);
  return;
};
void init_list(list_ht *ht) {
  // ht->head->next = NULL;
  // ht->tail->prev = NULL;
  // ht = (list_ht *)calloc(1, sizeof(list_ht));
  ht->head = (list_link_t *)calloc(1, sizeof(list_link_t));
  ht->tail = (list_link_t *)calloc(1, sizeof(list_link_t));
  ht->head->next = ht->tail;
  ht->tail->prev = ht->head;
  ht->head->prev = NULL;
  ht->tail->next = NULL;

}

void pq_insert(list_ht *ht, list_link_t *node, int (*compare_fn)(void*, void*)){
  
  list_link_t *to_be_compared = ht->head->next; // first element of this q
  // int i = 0;
  while(to_be_compared != ht->tail){
    int result;
    // result = compare_fn(data, to_be_compared);
    result = compare_fn(node, to_be_compared);
    if(result == 1) {
      // if bigger : Not here go to next
      to_be_compared = to_be_compared->next;
      continue;
    }
    else if(result == 0 || result == -1) {
      // cause it is not bigger than compared node, insert it here(break it)
      break;
    } else {
      printf("undefined behavior \n");
      return;
    }
  }

  // printf("i : %d\n", i);
  // 1) to_be_compared here : tail
  // cause this node has reached the end of the pq, simply insert it to the end of the pq

  // 2) second case : smaller
  to_be_compared->prev->next = node;
  node->prev = to_be_compared->prev;
  node->next = to_be_compared;
  to_be_compared->prev = node;
  // printf("check addr: %p\n", ht->head->next);
  return;
};
