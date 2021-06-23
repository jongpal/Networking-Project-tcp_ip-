#ifndef __LIST_H__
#define __LIST_H__

#define DATA_OFFSETS(struct_name, field_name) (unsigned int)(&((struct_name*)0)->field_name)


typedef struct list_ {
  struct list_ *next;
  struct list_ *prev;
} list_link_t;

typedef struct list_head_tail {
  struct list_ *head;
  struct list_ *tail;
} list_ht;


void add_list_front(list_ht *ht, list_link_t *entry);
void add_list_back(list_ht *ht, list_link_t *entry);
void remove_list(list_link_t *entry);
void init_list(list_ht *ht);
list_link_t* pop_list_back(list_ht *ht);
list_link_t* pop_list_front(list_ht *ht);

// where, this queue, data, function
void pq_insert(list_ht *ht, list_link_t *node, int (*compare_fn)(void*, void*));
#endif
