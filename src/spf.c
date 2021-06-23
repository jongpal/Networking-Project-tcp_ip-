#include "./../include/tcp_public.h"
#include "./../include/list.h"

#define INFINITE_METRIC 1000

extern void free_route_table(node_t *node);
typedef struct spf_result_{
  node_t *node; // to this node
  uint32_t spf_metric; // metric to reach this node from root node
  interface_t *dest_if[MAX_NXT_HOPS];
  char mask[MAX_NXT_HOPS];
  nexthop_t *nexthops[MAX_NXT_HOPS]; // root's nexthops to reach this node array : possible ECMP
  list_link_t spf_res;  // for multiple router it could reach
} spf_result_t;


// per node data structure
typedef struct spf_data {
  node_t *node; // this node (back pointer)
  list_ht spf_result_head; // for spf root
  // temp fields used for calculations
  uint32_t spf_metric;
  interface_t *dest_if[MAX_NXT_HOPS];
  char mask[MAX_NXT_HOPS];
  list_link_t priority_q;
  nexthop_t *nexthops[MAX_NXT_HOPS];
} spf_data_t;

#define spf_data_offset_from_priority_qhead ((size_t)&(((spf_data_t *)0)->priority_q))
#define spf_result_offset_from_spf_res ((size_t)&(((spf_result_t *)0)->spf_res))

#define SPF_METRIC(nodeptr) (nodeptr->spf_data->spf_metric)


void show_spf_results(node_t *node) {
  list_link_t *data = node->spf_data->spf_result_head.head->next;
  printf("---- shortest path first results for node %s---\n", node->name);
  while(data != node->spf_data->spf_result_head.tail) {
    spf_result_t *spf_res = (spf_result_t *)((char *)data - spf_result_offset_from_spf_res);
    printf("-to : %s-\ncost metric : %d\n", spf_res->node->name, spf_res->spf_metric);
    for(int i=0; i < MAX_NXT_HOPS; i++){
      // if(spf_res->nexthops+i == NULL) break;
      // printf("%d nexthop ip : %s, oif : %s\n",i,(spf_res->nexthops+i)->gw_ip, (spf_res->nexthops+i)->oif->name);
      if(spf_res->nexthops[i] == NULL) break;
      printf("%d nexthop ip : %s, oif : %s\n",i,spf_res->nexthops[i]->gw_ip, spf_res->nexthops[i]->oif->name);
    }
    data = data->next;
  }
  printf("------------------\n");
}
// testing
// array 마다 이걸 복사.ref count 개념 x
// void spf_free_nexthops(nexthop_t **nexthop) {

void spf_clear_nexthops(nexthop_t **nexthop) {
  if(!nexthop) return;
  int i = 0;
  while(i < MAX_NXT_HOPS) {
    if(nexthop[i] == NULL || nexthop[i]->oif == NULL) {
      i++;
      continue;
    }
    else {
      //printf("clearing ... %s %d\n", nexthop[i]->oif->name, nexthop[i]->ref_count);
      // free(nexthop[i]);
      nexthop[i] = NULL;
      // memset(nexthop[i], 0, sizeof(nexthop_t));
    }
    i++;
  }

}
void free_nexthops(nexthop_t **nexthop) {
  if(!nexthop) return;
  int i = 0;
  while(i < MAX_NXT_HOPS) {
    if(nexthop[i] == NULL || nexthop[i]->oif == NULL) {
      i++;
      continue;
    }
    else {
      //printf("freeing ... %s %d\n", nexthop[i]->oif->name, nexthop[i]->ref_count);
      free(nexthop[i]);
    }
    i++;
  }

}


// void spf_flush_nexthops(nexthop_t **nexthop){
void spf_flush_nexthops(nexthop_t **nexthop){
  if(!nexthop) return;
  int i = 0;
  while(i < MAX_NXT_HOPS) {
    if(nexthop[i] == NULL) {
      i++;
      continue;
    }
    if(nexthop[i]->ref_count > 0) {
      nexthop[i]->ref_count --;
     // printf("now nexthop with oif %s ref count : %d\n", nexthop[i]->oif->name, nexthop[i]->ref_count);
	  
    }
    if((nexthop[i])->ref_count == 0){
      printf("freeing nexthop with oif %s\n", nexthop[i]->oif->name);
      free(nexthop[i]);
      // nexthop[i] = NULL;
      

      // i++;
      // continue;
    }
    i++;
  }
  
}
// => spf data 의 nexthop info들을 지운다. (link state 알고리즘이 실행되면서 link state pkt 이 nexthop으로 나가고 나서 불려질 것임

static void free_spf_results(spf_result_t *spf_result){
  //
  // spf_flush_nexthops(spf_result->nexthops);
  //
  // spf_clear_nexthops(spf_result->nexthops);
  free_nexthops(spf_result->nexthops);
  //  remove_list(s 
//  remove_list(&spf_result->spf_res);
  free(spf_result);
};

static nexthop_t *create_nexthop(interface_t *oif) {
  interface_t *next_intf = get_nbr_node_intf(oif);
  if(is_interface_l3_bidirectional(oif) == FALSE) return NULL;
  if(!next_intf) return NULL;

  nexthop_t *nexthop = (nexthop_t *)calloc(1, sizeof(nexthop_t));
  memcpy(nexthop->gw_ip, next_intf->intf_nw_props.ip_add.ip_addr, IP_LENGTH);

  nexthop->oif = oif;
  // nexthop->oif = (interface_t *)calloc(1, sizeof(interface_t));
  // memcpy(nexthop->oif, oif, sizeof(interface_t));
  nexthop->ref_count = 0;
  return nexthop;
}

static bool_t spf_insert_nexthop(interface_t *if_to_insert, nexthop_t **nexthops, nexthop_t *new_next){

  for(int cur=0; cur < MAX_NXT_HOPS; cur++){
    if(nexthops[cur] != NULL) continue;
    // memcpy(nexthops[cur]->gw_ip, new_next->gw_ip, IP_LENGTH);
    // nexthops[cur]->ref_count = new_next->ref_count;
    // memcpy(nexthops[cur]->oif, new_next->oif, sizeof(interface_t));
    
    nexthops[cur] = new_next;
        
    if(if_to_insert) if_to_insert->node->spf_data->dest_if[cur] = if_to_insert;
    //
    // nexthops[cur]->ref_count +=1;
    // printf("INSERT now nexthop with oif %s ref count : %d\n", nexthops[cur]->oif->name, nexthops[cur]->ref_count);
    //
    //printf("INSERT now nexthop with oif %s\n", nexthops[cur]->oif->name);
    return TRUE;
  }
  return FALSE;
}

static nexthop_t * spf_is_nexthop(nexthop_t **nexthops, nexthop_t *nexthop) {
  for(int cur=0; cur < MAX_NXT_HOPS; cur++){
    if(nexthops[cur] == NULL) continue;
    if(!strncmp(nexthops[cur]->gw_ip, nexthop->gw_ip, IP_LENGTH)){
      return nexthops[cur];
    };
  }
  return NULL;
}

static int spf_union_nexthop_arrays(nexthop_t **src, nexthop_t **dst){
  //find the end point of src, from that point on, cpy the nexhop infos of dst

  // first, loop dst, check if overlapping one by one
  //should exclude the overlapping nexthop arrays

  int j = 0;
  for(int i = 0 ; i< MAX_NXT_HOPS; i++) {
    while(dst[j] != NULL) j++;
    //
    // if(src[i] == NULL) continue;
    //
    if(src[i] == NULL || src[i]->oif == NULL) continue;
    nexthop_t *nxthop;
    if((nxthop = spf_is_nexthop(dst, src[i])) != NULL) {
      nxthop->ref_count += 1;
      continue;
    }
    else {
      dst[j] = (nexthop_t *)calloc(1, sizeof(nexthop_t));
      memcpy(dst[j], src[i], sizeof(nexthop_t));
    }
   
    //
    // dst[start_from_here] = (nexthop_t *)calloc(1, sizeof(nexthop_t));
    // memcpy(dst[start_from_here], src[i], sizeof(nexthop_t));
    //
    //
    // dst[start_from_here] = src[i];
    // dst[start_from_here]->ref_count += 1;
    //
    // start_from_here++;
  }
  

  return 0;
}

// data2(which will be compared) would point to the link_list_t member inside of spf_data_t struct
int spf_compare_fn(void *data1, void *data2){
  //data is now pointing to the list_link data of spf_data_t , so you should point it up to point to spf_data_t
  data1 = (char*)data1 - spf_data_offset_from_priority_qhead;
  data2 = (char*)data2 - spf_data_offset_from_priority_qhead;

  spf_data_t *spf_data_1 = (spf_data_t *)data1;
  spf_data_t *spf_data_2 = (spf_data_t *)data2;

  
  if(spf_data_1->spf_metric < spf_data_2->spf_metric) return -1;
  if(spf_data_1->spf_metric > spf_data_2->spf_metric) return 1;
  return 0; // same
}

static spf_result_t *spf_lookup_spf_result_by_node(node_t *spf_root, node_t *node_){
  list_link_t *cur = spf_root->spf_data->spf_result_head.head->next;
  list_link_t *endcur = spf_root->spf_data->spf_result_head.tail;
  while(cur != endcur){
    // unsigned int list_offset = DATA_OFFSETS(spf_result_t, spf_res);
    unsigned int list_offset = spf_result_offset_from_spf_res;
    // node_t *spf_node = (node_t *)((char *)cur - list_offset);
    spf_result_t *spf_node = (spf_result_t *)((char *)cur - list_offset);
    if(strncmp(spf_node->node->name, node_->name, NODE_NAME_SIZE) == 0) return spf_node;
    // if(strncmp(spf_node->name, node_->name, NODE_NAME_SIZE) == 0) return (spf_result_t *)spf_node;
    cur = cur->next;
  }
  return NULL;
}
static void init_node_spf_data(node_t *node, bool_t is_root) {
  if(node->spf_data == NULL) {
    node->spf_data = (spf_data_t *)calloc(1, sizeof(spf_data_t));
    // node->spf_data->node = (node_t *)calloc(1, sizeof(node_t));
    // memcpy(node->spf_data->node, node, sizeof(node_t));
    node->spf_data->node = node;
    // init_list(&node->spf_data->spf_result_head);
  }
  // if is_root => should delete spf_results
  if(is_root == TRUE) {
    if(node->spf_data->spf_result_head.head == NULL || node->spf_data->spf_result_head.tail == NULL) {
       if(node->spf_data->spf_result_head.head != NULL)free(node->spf_data->spf_result_head.head);
       if(node->spf_data->spf_result_head.tail != NULL)free(node->spf_data->spf_result_head.tail);
       init_list(&node->spf_data->spf_result_head);
    }
    list_link_t *cur = node->spf_data->spf_result_head.head->next;
    list_link_t *endcur = node->spf_data->spf_result_head.tail;
    while(cur != endcur) {
      // unsigned int list_offset = DATA_OFFSETS(spf_result_t, spf_res);
      // spf_result_t *spf_result_ = (spf_result_t *)(cur - list_offset);
      
      spf_result_t *spf_result_ = (spf_result_t *)((char *)cur - spf_result_offset_from_spf_res);
      free_spf_results(spf_result_);
      cur = cur->next;
    }
	// after erase : init the pq 
	node->spf_data->spf_result_head.head->next = node->spf_data->spf_result_head.tail;
    node->spf_data->spf_result_head.tail->prev = node->spf_data->spf_result_head.head;
    // free(node->spf_data->spf_result_head.head);
    // free(node->spf_data->spf_result_head.tail);
    // node->spf_data->spf_metric = 0;
    SPF_METRIC(node) = 0; // cost : 0 for root
  }
  // else : should initialize the metric to infinity
  else {
    SPF_METRIC(node) = INFINITE_METRIC;
  }
  // empty the priority queue
  remove_list(&node->spf_data->priority_q);
  //free nexthops
  // spf_flush_nexthops(node->spf_data->nexthops);
  //
  spf_clear_nexthops(node->spf_data->nexthops);
}

//relax the nbrs using link cost
void spf_init_direct_nbrs (node_t *spf_root) {
  int until = get_node_intf_available_slot(spf_root);
  // until = until > MAX_NXT_HOPS ? MAX_NXT_HOPS : until;
  for(int i=0 ; i <until; i++) {
    // lookup nexthops of spf_data
    interface_t *oif = spf_root->if_list[i];
    if(is_interface_l3_bidirectional(oif) == FALSE) continue;
    interface_t *nbr_if = get_nbr_node_intf(oif);
    // nexthop_t *new_nxt_hop = create_nexthop(oif);

    unsigned int link_cost= spf_root->spf_data->spf_metric;
    // printf("link cost : %d\n", oif->link->cost);
    //printf("oif %s link cost : %d, SPF_METRIC : %d\n", oif->name,link_cost, SPF_METRIC(nbr_if->node));
    link_cost += oif->link->cost;
    if(SPF_METRIC(nbr_if->node) > link_cost) {
      nexthop_t *new_nxt_hop = create_nexthop(oif);
      //
      // spf_flush_nexthops(nbr_if->node->spf_data->nexthops);
      //
      spf_clear_nexthops(nbr_if->node->spf_data->nexthops);
      // spf_insert_nexthop(spf_root->spf_data->nexthops, new_nxt_hop);
      // memcpy(nbr_if->node->spf_data->nexthops, spf_root->spf_data, )
      spf_insert_nexthop(0, nbr_if->node->spf_data->nexthops, new_nxt_hop);
      //printf("new cost for node %s : %d\n", nbr_if->node->name,link_cost);
      SPF_METRIC(nbr_if->node) = link_cost;
    }
    else if(SPF_METRIC(nbr_if->node) == link_cost) {
      //ECMP : append it
      // spf_insert_nexthop(spf_root->spf_data->nexthops, new_nxt_hop);
      // append only if it is not already added
      nexthop_t *new_nxt_hop = create_nexthop(oif);
      if(spf_is_nexthop(nbr_if->node->spf_data->nexthops, new_nxt_hop) == NULL) spf_insert_nexthop(0, nbr_if->node->spf_data->nexthops, new_nxt_hop);
      else free(new_nxt_hop);
    }
    // if none of the content : insert
    // if there are some contents : check if overlapping interface 
    // if interface overlapped : find smallest cost
    // spf_root->if_list[i]->
    // iterate, found new intf => add it to nexthop info. if existed intf => compare the cost and update
  }
}

static void spf_explore_nbrs(node_t *node) {

}

static void spf_record_result(node_t *spf_root, node_t *to_record){
  spf_result_t *spf_result = (spf_result_t *)calloc(1, sizeof(spf_result_t));
  spf_result->spf_metric = to_record->spf_data->spf_metric;
  // spf_result->node = (node_t *)calloc(1, sizeof(node_t));
  // memcpy(spf_result->node, to_record->spf_data->node, sizeof(node_t));
  //
  spf_result->node = to_record->spf_data->node;
  //
  spf_union_nexthop_arrays(to_record->spf_data->nexthops, spf_result->nexthops);
  int n = 0;
  while(to_record->spf_data->dest_if[n] != NULL){
    spf_result->dest_if[n] = to_record->spf_data->dest_if[n];
    spf_result->mask[n] = to_record->spf_data->mask[n];
    n++;
  }
  
  add_list_back(&spf_root->spf_data->spf_result_head, &spf_result->spf_res);
  return;
}

void spf_install_route_result(node_t *spf_root){
  list_link_t *data = spf_root->spf_data->spf_result_head.head->next;
  while(data != spf_root->spf_data->spf_result_head.tail) {
    spf_result_t *res = (spf_result_t *)((char *)data - spf_result_offset_from_spf_res);
    
    for(int i=0 ;i < MAX_NXT_HOPS; i++) {
      if(res->nexthops[i] == NULL) continue;
	        printf("installing : dst %s, gw ip %s, oif %s\n", res->node->node_nw_props.lb_add.ip_addr, res->nexthops[i]->gw_ip, res->nexthops[i]->oif->name);
      add_route_entry(spf_root, res->node->node_nw_props.lb_add.ip_addr, 32, res->nexthops[i]->gw_ip, res->nexthops[i]->oif, res->spf_metric);
	  int n = 0;
      while(res->dest_if[n] != NULL) {

        printf("installing : dst %s, gw ip %s, oif %s\n", res->dest_if[n]->intf_nw_props.ip_add.ip_addr, res->nexthops[i]->gw_ip, res->nexthops[i]->oif->name);
        add_route_entry(spf_root, res->dest_if[n]->intf_nw_props.ip_add.ip_addr, res->mask[n], res->nexthops[i]->gw_ip, res->nexthops[i]->oif, res->spf_metric);
        n++;
      }
      // free_spf_results(res);
    }
    data = data->next;
  }
};

void compute_spf(ctrl_table_t *topo, node_t *spf_root){  
  //free_route_table(spf_root);
  init_node_spf_data(spf_root, TRUE);
  int curr_size = topo->curr_size;

  //init other nodes on topology
  int curr = 0;
  
  graph_elements_t *graph_el = topo->table_ptr;
  while(curr < curr_size) {
    if(graph_el->is_entry) {
      node_t *node_ = (node_t *)graph_el->entry;
      if(strncmp(node_->name, spf_root->name, NODE_NAME_SIZE) != 0) init_node_spf_data(node_, FALSE);
      curr++;
    }
    graph_el++;
  }
  spf_init_direct_nbrs(spf_root);
  list_ht *pq_ht = (list_ht *)calloc(1, sizeof(list_ht)); // priority queue head

  //insert spf root first
  init_list(pq_ht);
  
  pq_insert(pq_ht, &spf_root->spf_data->priority_q, spf_compare_fn);
  spf_data_t *pq_check = (spf_data_t *)((char *)pq_ht->head->next - spf_data_offset_from_priority_qhead);
  // printf("pq front : %s\n", pq_check->node->name);
  list_link_t *pq_cur = pq_ht->head;
  // 여기부터
  while(pq_cur->next != pq_ht->tail) {
    list_link_t *popped = pop_list_front(pq_ht);
    spf_data_t *popped_spf = (spf_data_t *)((char *)popped - spf_data_offset_from_priority_qhead);
    //printf("pq popped : %s => cost %d\n", popped_spf->node->name, popped_spf->spf_metric);
    if(strncmp(popped_spf->node->name, spf_root->name, NODE_NAME_SIZE) == 0){
      // if spf_root => exlore nbr;
      // consult nxt interface's info
    
      // spf_explore_nbrs(spf_root);
      int until = get_node_intf_available_slot(spf_root);
      for(int i=0; i < until; i++) {
        interface_t *outgoing_if = spf_root->if_list[i];
        interface_t *nbr_interface = get_nbr_node_intf(outgoing_if);
        if(spf_lookup_spf_result_by_node(spf_root, nbr_interface->node) == NULL) {
          if(is_interface_l3_bidirectional(outgoing_if) == FALSE) continue;
          //then it is allowed to append to priority queue
          // printf("from root node , pq insert : %s\n", nbr_interface->node->name);
          pq_insert(pq_ht, &nbr_interface->node->spf_data->priority_q, spf_compare_fn);
        }
      }
    } else {
      // making spf_result data, add it to spf_result queue (just append)
      spf_record_result(spf_root, popped_spf->node);

      //explore the nbr

      // loop the nbr one by one
        // from node's interface data
          // you should simulate the process of nexthop datas spreading through entire graph
      int until = get_node_intf_available_slot(popped_spf->node);
      for(int i=0; i < until; i++) {
        unsigned int cur_cost = popped_spf->spf_metric;
      // for each nbr, check the validity of that nbr first
        interface_t *out_intf = popped_spf->node->if_list[i];
        // if already visited : 
        if(is_interface_l3_bidirectional(out_intf) == FALSE) {
          printf("not bidirectional : oif %s\n", out_intf->name);
          continue;
        }
        cur_cost += out_intf->link->cost;
        interface_t *nbr_intf = get_nbr_node_intf(out_intf);
        //if already visited node or if it is root node, continue
        spf_result_t *test_res;
        if((test_res = spf_lookup_spf_result_by_node(spf_root, nbr_intf->node)) != NULL || strncmp(nbr_intf->node->name, spf_root->name, NODE_NAME_SIZE) == 0) continue;
        // if it is valid nbr, calculate the spf metric : compare (link cost + this node's metric) and the metric of this nbr
        // case 1 : x + m < y
        if(cur_cost < SPF_METRIC(nbr_intf->node)) {
          SPF_METRIC(nbr_intf->node) = cur_cost;
          // new shorter path
          // delete the existing nexthops and update with new one
          //
          // spf_flush_nexthops(nbr_intf->node->spf_data->nexthops);
          //
          spf_clear_nexthops(nbr_intf->node->spf_data->nexthops);

          int n = 0;
          while(nbr_intf->node->spf_data->dest_if[n] != NULL){
            nbr_intf->node->spf_data->mask[n] = -1;
            nbr_intf->node->spf_data->dest_if[n] = NULL;
            n++;
          }
          nbr_intf->node->spf_data->mask[0] = nbr_intf->intf_nw_props.mask;
          nbr_intf->node->spf_data->dest_if[0] = nbr_intf;

          spf_union_nexthop_arrays(popped_spf->nexthops, nbr_intf->node->spf_data->nexthops);
          // for priority queue : if already exists : delete and add again for update
          if(nbr_intf->node->spf_data->priority_q.next != NULL) {
            // printf("removing..\n");
            remove_list(&nbr_intf->node->spf_data->priority_q);
          }
          // printf("pq insert : %s, cur cost : %d\n", nbr_intf->node->name, cur_cost);
          pq_insert(pq_ht, &nbr_intf->node->spf_data->priority_q, spf_compare_fn);

          list_link_t *checking = pq_ht->head->next;
          // printf("pq check : %s, %d\n", ((spf_data_t *)((char *)checking-spf_data_offset_from_priority_qhead))->node->name, pq_ht->head->next->next == pq_ht->tail);
        }
        // case 2 : x + m = y => ECMP (just make a union of both of nodes)
        else if(cur_cost == SPF_METRIC(nbr_intf->node)) {
          //printf("ECMP case for %s\n", nbr_intf->node->name);

          int n=0;
          while(nbr_intf->node->spf_data->dest_if[n] != NULL){
            if(nbr_intf->node->spf_data->dest_if[n] == nbr_intf) {
              n = -1;
              break;
            }
            else n++;
          }
          if(n != -1) {
            nbr_intf->node->spf_data->mask[n] = nbr_intf->intf_nw_props.mask;
            nbr_intf->node->spf_data->dest_if[n] = nbr_intf;
          }

          spf_union_nexthop_arrays(popped_spf->nexthops, nbr_intf->node->spf_data->nexthops);
        }
        // case 3 : x + m > y => which is useless, so just ignore it
      
      }
      // popped_spf->
      // log nexthop
      for(int i=0; i< MAX_NXT_HOPS;i++){
        if(popped_spf->nexthops[i] == NULL) break;
        //printf("for %s nexthop %d : oif=>%s, count : %d\n", popped_spf->node->name, i,popped_spf->nexthops[i]->oif->name, popped_spf->nexthops[i]->ref_count);
      }
      //
      // spf_flush_nexthops(popped_spf->nexthops);
      //

      // spf_free_nexthops(popped_spf->nexthops);
      free_nexthops(popped_spf->nexthops);
    }
  }
  // install the routing results
  spf_install_route_result(spf_root);
  //after calulation / installation : free pq_ht
  free(pq_ht);
}
void compute_spf_all_routers(ctrl_table_t *topo){
  // loop the topology
  int until = topo->curr_size;
  graph_elements_t *graph_el = topo->table_ptr;
  int curr = 0;
  while(curr < until) {
    if(graph_el->is_entry) {
      node_t *node = (node_t *)graph_el->entry;
      compute_spf(topo, node);
      curr++;
    }
    graph_el++;
  }
  // execute compute_spf for each node
};
