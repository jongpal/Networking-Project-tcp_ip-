#include "../include/layer3.h"
#include "../include/utils.h"
#include "../include/tcpconst.h"
#include "../include/layer4.h"
#include <assert.h>


extern void rt_hash_display(ctrl_table_t *hashTable);
extern void promote_pkt_to_l5(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type);
extern void promote_pkt_to_l4(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type);
extern void free_nexthops(nexthop_t **nexthop);

static void process_icmp_echo_request(node_t *node, char *recvd_ip_header, interface_t *recvd_intf,unsigned int payload_size);
static void process_router_solicitation_request(node_t *node, uint32_t dest_ip);
static void mk_router_discovery_msg(node_t *node, char *new_payload, unsigned int *payload_size);
static void process_router_discovery_request(node_t *node, char *payload, interface_t *recv_intf, unsigned int payload_size);

void init_ip_hdr_default(ip_hdr_t *ip_hdr){
  ip_hdr->version = 4;
  ip_hdr->IHL = 5; //20Bytes (1 unit : 4 bytes) 
  ip_hdr->type_of_service = 0;
  ip_hdr->tot_length = 0;
  ip_hdr->identification = 0;
  ip_hdr->unused_flag = 0;
  ip_hdr->DF_flag = 1;
  ip_hdr->MORE_flag = 0;
  ip_hdr->frag_offset = 0;

  ip_hdr->ttl = 64;
  ip_hdr->protocol = 0;
  ip_hdr->ip_hdr_checksum = 0;
  ip_hdr->src_ip = 0;
  ip_hdr->dest_ip = 0;

};

int ret_nxthop_idx (rt_entry_t *rt_entry) {
  int idx = rt_entry->nxthop_idx;
  // if reached the end : MAX_NXT_HOPS => make it circular
  if(idx == MAX_NXT_HOPS - 1) rt_entry->nxthop_idx = 0;
  // if next ecmp exist : increase idx
  else if(rt_entry->nxt_hops[idx+1] != NULL) rt_entry->nxthop_idx ++;
  // if not : idx is still idx

  return idx;
}

void init_route_table(node_t *node){
  if(node->node_nw_props.rt_table_manager != NULL) free(node->node_nw_props.rt_table_manager);
  // free(node->node_nw_props.rt_table_manager->hea)

  node->node_nw_props.rt_table_manager = (rt_ht *)calloc(1, sizeof(rt_ht));
  // node->node_nw_props.rt_table_manager->head = NULL;
  // node->node_nw_props.rt_table_manager->tail = NULL;
  node->node_nw_props.rt_table_manager->head = NULL;
  node->node_nw_props.rt_table_manager->tail = NULL;
};

// rt_entry_t* add_route_entry(node_t *router, char *dst, char mask, char *gw, char*oif, unsigned char cost) {
rt_entry_t* add_route_entry(node_t *router, char *dst, char mask, char *gw, interface_t *oif, unsigned char cost) {
  // search 먼저 : 같은 dest ip, mask 가진놈 있다 ? ecmp 케이스로 추가, 아니다 : 그냥 새로운 엔트리 malloc 후 추가
  

  // free 전에 거 안해줘서 ? init 루틴 부터 실행하기 (새로 만들어서 )
  rt_entry_t *rt_entry = lookup_rt_table(router, ip_addr_p_to_n(dst));
  // dump_rt_table(router);
  if(rt_entry != NULL) {
    int empty_idx;
    char check = 0;
    // ECMP case if gw is different
    for(int i =0; i<MAX_NXT_HOPS; i++) {
      if(rt_entry->nxt_hops[i] == NULL) {
        if(check == 0) {
          empty_idx = i;
          check = 1;
        }
        continue;
      }
	  else if(strncmp(rt_entry->nxt_hops[i]->gw_ip, gw, IP_LENGTH) == 0 && rt_entry->cost_metric != cost) {
        // update
        rt_entry->cost_metric = cost;
        return rt_entry;
      }
      else if(strncmp(rt_entry->nxt_hops[i]->gw_ip, gw, IP_LENGTH) == 0) {
        printf("duplicate route entry, ip : %s\n", dst);
        return NULL;
      }
    }
    nexthop_t *new_nxthop = (nexthop_t *)calloc(1, sizeof(nexthop_t));
    memcpy(new_nxthop->gw_ip, gw, IP_LENGTH);
    new_nxthop->ref_count = 0;
    new_nxthop->oif = oif;
    rt_entry->nxt_hops[empty_idx] = new_nxthop;
    rt_entry->cur_ecmp_num ++;
    return rt_entry;
  }
  //if rt_entry is NULL(no search result) : create new entry
  bool_t is_direct = FALSE;
  if(gw == NULL || oif == NULL) is_direct= TRUE;
  // set entry
  rt_entry_t *new_rt_entry = (rt_entry_t *)calloc(1, sizeof(rt_entry_t));
  // new_rt_entry->nxt_hops[0] = NULL;
  // new_rt_entry->nxt_hops[1] = NULL;
  // new_rt_entry->nxt_hops[2] = NULL;
  // new_rt_entry->nxt_hops[3] = NULL;
  new_rt_entry->is_direct = is_direct;
  new_rt_entry->is_svi_configured = FALSE;

  nexthop_t *nxt_info;
  // nexthop_t *nxt_info = new_rt_entry->nxt_hops[0];
  new_rt_entry->nxthop_idx = 0;
  new_rt_entry->cur_ecmp_num = 0;
  nxt_info = (nexthop_t *)calloc(1, sizeof(nexthop_t));
  nxt_info->ref_count = 0;

  new_rt_entry->mask = mask;
  apply_mask(dst, mask, new_rt_entry->dest_ip);
  new_rt_entry->cost_metric = cost;
  if(oif) {
    // 일단 여기서 한개만 준다고 가정
    // memcpy(nxt_infos->oif, oif, IF_NAME_SIZE);
    // rt_entry->nxt_hops[0] = nxt_infos;
    //
    // memcpy(rt_entry->oif, oif, IF_NAME_SIZE);
    //
    nxt_info->oif = oif;
  }
  if(gw){ 
    // memcpy(nxt_infos->gw_ip, gw, IP_LENGTH);
    // rt_entry->nxt_hops[0] = nxt_infos;
    // 
    // memcpy(rt_entry->gw_ip, gw, IP_LENGTH);
    //
    memcpy(nxt_info->gw_ip, gw, IP_LENGTH);
  }
  else {
    memcpy(nxt_info->gw_ip, "N/A", strlen("N/A")+1);
  }

  new_rt_entry->nxt_hops[0] = nxt_info;
  new_rt_entry->cur_ecmp_num ++;
  // if newly created node (head will point to NULL)
  
  if(router->node_nw_props.rt_table_manager->head == NULL) {
    route_node *rt_node = (route_node *)calloc(1, sizeof(route_node));
    rt_node->key = mask;
    rt_node->rt_table = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
    rt_node->next = NULL;  
    rt_node->prev = NULL;  
    router->node_nw_props.rt_table_manager->head = rt_node;
    router->node_nw_props.rt_table_manager->tail = rt_node;

    // enum type t = rt->table_type;
    make_hash_table(rt_node->rt_table, 2, ROUTER_T);
    init_hash_table(rt_node->rt_table, ROUTER_T);

    if(insert(rt_node->rt_table, new_rt_entry) == NULL) return NULL;
    return rt_entry;
  }
  //list lookup
  route_node* curr = router->node_nw_props.rt_table_manager->head;
  route_node* tail = router->node_nw_props.rt_table_manager->tail;
  char head_key = router->node_nw_props.rt_table_manager->head->key;

  while(curr != NULL){
    //current key is bigger
    if(curr->key > mask) {
      //tail
      if(curr->next == NULL) {
        route_node *rt_node = (route_node *)calloc(1, sizeof(route_node));
        rt_node->key = mask;
        rt_node->rt_table = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));    
        rt_node->next = curr->next;
        rt_node->prev = curr;
        curr->next = rt_node; 
        tail = rt_node;

        make_hash_table(rt_node->rt_table, 2, ROUTER_T);
        init_hash_table(rt_node->rt_table, ROUTER_T);

        if(insert(rt_node->rt_table, new_rt_entry) == NULL) return NULL;
        return rt_entry;   
      }
      curr = curr->next;
      continue;
    }
    //smaller
    if(curr->key < mask) {
      //insert
      route_node *rt_node = (route_node *)calloc(1, sizeof(route_node));
      rt_node->key = mask;
      rt_node->rt_table = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));

      rt_node->next = curr; 
      rt_node->prev = curr->prev;
      // if head
      if(curr->prev == NULL){
        router->node_nw_props.rt_table_manager->head = rt_node;
        curr->prev = rt_node;
      } else {
        curr->prev->next = rt_node;
        curr->prev = rt_node;
      }

      make_hash_table(rt_node->rt_table, 2, ROUTER_T);
      init_hash_table(rt_node->rt_table, ROUTER_T);

      if(insert(rt_node->rt_table, new_rt_entry) == NULL) return NULL;
      return rt_entry;        
    }
    //same
    // printf("helllllo %s, oif %s\n", new_rt_entry->dest_ip, new_rt_entry->nxt_hops[0]->oif->name);
    if(insert(curr->rt_table, new_rt_entry) == NULL) return NULL;
    return new_rt_entry;  
  }
  printf("undefined behavior \n");
  return NULL;
}

rt_entry_t *lookup_rt_table (node_t *rt, unsigned int dst_ip){
  route_node *curr = rt->node_nw_props.rt_table_manager->head;
  char ip[IP_LENGTH];
  char masked_ip[IP_LENGTH];
  rt_entry_t *found_entry = NULL;
  ip_addr_n_to_p(dst_ip, ip);

  while(curr != NULL){
    apply_mask(ip, curr->key, masked_ip);
    if((found_entry = search(curr->rt_table, masked_ip)) == NULL) {
      curr = curr->next;
      continue; 
    };
    break;
  }
  
  //if(found_entry == NULL) printf("no result");
  //else printf("found, %s\n", found_entry->dest_ip);

  return found_entry;
};

void free_route_table(node_t *node) {
  if(node->node_nw_props.rt_table_manager->head == NULL && node->node_nw_props.rt_table_manager->tail == NULL) return;

  while(node->node_nw_props.rt_table_manager->head != node->node_nw_props.rt_table_manager->tail) {
    route_node *rn = node->node_nw_props.rt_table_manager->head;

    int cur_size = rn->rt_table->curr_size;
    int curr = 0;
    int idx = 0;
    while(curr < cur_size) {
      graph_elements_t *cur_graph = rn->rt_table->table_ptr+idx;
      if(cur_graph->is_entry){
        curr++;
        rt_entry_t *rt_entry = (rt_entry_t *)(cur_graph->entry);
        free_nexthops(rt_entry->nxt_hops);
        // if(rt_entry){
        //   for(int i = 0 ; i < rt_entry->cur_ecmp_num; i++) {
        //     if(rt_entry->nxt_hops[i] != NULL) free(rt_entry->nxt_hops[i]);
        //   }
        //   free(rt_entry);
        // }
        free(rt_entry);
      }
        // free(cur_graph);
        idx++;
    }
    free(rn->rt_table);
    if(rn == node->node_nw_props.rt_table_manager->head) {
      node->node_nw_props.rt_table_manager->head = rn->next;
      rn->next->prev = NULL;
    }
    else {
      rn->prev->next = rn->next;
      rn->next->prev = rn->prev;
    }
    free(rn);
  }
  node->node_nw_props.rt_table_manager->head = NULL;
  node->node_nw_props.rt_table_manager->tail = NULL;
}

static void send_pkt_to_default_gw(node_t *node, char *pkt, int protocol_number, unsigned int dest_ip){
  ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt;
  rt_entry_t *default_gw = lookup_rt_table(node, ip_addr_p_to_n(node->node_nw_props.default_gw.ip_addr));
  // printf("%s, %s ,%s\n", default_gw->gw_ip, default_gw->dest_ip, default_gw->oif);
  // interface_t *oif_ = get_node_if_by_name(node, default_gw->oif);
  interface_t *oif_ = default_gw->nxt_hops[0]->oif;

  ip_hdr->src_ip = ip_addr_p_to_n(oif_->intf_nw_props.ip_add.ip_addr);

  demote_pkt_to_l2(node, ip_addr_p_to_n(default_gw->nxt_hops[0]->gw_ip), pkt, ip_hdr->tot_length * 4, oif_, ETH_IP, 0);
  // demote_pkt_to_l2(node, ip_addr_p_to_n(default_gw->gw_ip), pkt, ip_hdr->tot_length * 4, default_gw->oif, ETH_IP, 0);
  return;
}

static void l3_recv_pkt_from_above(node_t *node, char *pkt, unsigned int data_size, int protocol_number, unsigned int dest_ip){

  ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt;

  init_ip_hdr_default(ip_hdr);
  //ip_addr_p_to_n api already did the host to network byte align
  // unsigned int src_lb_addr = ip_addr_p_to_n(NODE_LO_ADDR(node));
  ip_hdr->dest_ip = dest_ip;
  ip_hdr->protocol = protocol_number;
  ip_hdr->tot_length = ip_hdr->IHL + data_size / 4 + (data_size % 4 == 0 ? 0 : 1);

  //set src ip 
  rt_entry_t *rt_entry;
  if((rt_entry = lookup_rt_table(node, dest_ip)) == NULL) {  
    // if solicit address(multicast)
    if((*node->node_nw_props.solicit_addr.ip_addr) != 0 && ip_addr_p_to_n(node->node_nw_props.solicit_addr.ip_addr) == dest_ip) {
      //multicast : send out
      printf("\nsending out multicast ..\n");
      int until = get_node_intf_available_slot(node);
      for(int i=0; i < until; i++){
        printf("sending out at interface %s\n", node->if_list[i]->name);
        // mobile node's lb address
        ip_hdr->src_ip = ip_addr_p_to_n(NODE_LO_ADDR(node));
        demote_pkt_to_l2(node, 0, pkt, ip_hdr->tot_length * 4, node->if_list[i], ETH_IP, 0);
      }
      return;
    }
    else {
      printf("no matching routing result \n");
      // to the default gateway ip 
      send_pkt_to_default_gw(node, pkt, protocol_number, dest_ip);

      return;
    }
  }
  char ip_char[IP_LENGTH];
  ip_addr_n_to_p(dest_ip, ip_char);

  int nxt_idx = ret_nxthop_idx(rt_entry);
  interface_t *outgoing_if = rt_entry->nxt_hops[nxt_idx]->oif;
  // interface_t *outgoing_if = get_node_if_by_name(node, rt_entry->oif);
  ip_hdr->src_ip = ip_addr_p_to_n(outgoing_if->intf_nw_props.ip_add.ip_addr);

  switch(rt_entry->is_direct){
    case TRUE: {
      
      interface_t *matched_if = node_get_matching_subnet_interface(node, ip_char);
      if(matched_if->intf_nw_props.is_ip_config == FALSE) {
        printf("ip not configured in inferface\n");
        return;
      }
      //if exact match
      if(strncmp(IF_IP(matched_if), ip_char, IP_LENGTH) == 0 || strncmp(NODE_LO_ADDR(node), ip_char, IP_LENGTH) == 0) {
        //pkt is pointing to the start of ip hdr
        //oif -> NULL which means self ping
        demote_pkt_to_l2(node, 0, pkt, ip_hdr->tot_length * 4, 0, ETH_IP, 0);
        return;
      }
      // nexthop ip=0 for local subnet
      
      // demote_pkt_to_l2(node, 0, pkt, ip_hdr->tot_length*4, rt_entry->oif, ETH_IP, 0);
      demote_pkt_to_l2(node, 0, pkt, ip_hdr->tot_length*4, outgoing_if, ETH_IP, 0);
      return;
    }
    case FALSE: {
      // convert_ip_from_str_to_int(rt_entry->gw_ip)
      demote_pkt_to_l2(node, ip_addr_p_to_n(rt_entry->nxt_hops[nxt_idx]->gw_ip), pkt, ip_hdr->tot_length*4, outgoing_if, ETH_IP, 0);
      // demote_pkt_to_l2(node, ip_addr_p_to_n(rt_entry->gw_ip), pkt, ip_hdr->tot_length*4, rt_entry->oif, ETH_IP, 0);
      return;
    }
  }
}

void demote_pkt_to_l3(node_t *node, char *data, unsigned int data_size, int protocol_number, unsigned int dest_ip){
  // assuming l5 allocated enough buffer size infront of its data : so we can just add hdr at the front
  char *pkt = data - sizeof(ip_hdr_t);
  l3_recv_pkt_from_above(node, pkt, data_size, protocol_number, dest_ip);
  return;
};

void dump_rt_table(node_t *rt){
  route_node *head = rt->node_nw_props.rt_table_manager->head;
  int i  = 0;
  while(head != NULL) {
    i++;
    printf("--- %d --- \n", i);
    rt_hash_display(head->rt_table);
    head = head->next;
  }
}

bool_t is_exact_match(node_t *node, char *ip_addr){
  int until = get_node_intf_available_slot(node);
  for(int i = 0; i<until; i++){
    if(strncmp(IF_IP(node->if_list[i]), ip_addr, IP_LENGTH) == 0) return TRUE;
  }
  return FALSE;
}

void l3_rcv_ip_frame_from_bottom(node_t *node, interface_t *recv_intf, char* payload, int protocol_number, unsigned int payload_size){
  ip_hdr_t* ip_hdr = (ip_hdr_t *)payload;
  char ip[16];
  ip_addr_n_to_p(ip_hdr->dest_ip, ip);
  //check checksum for IPv4
  // char *payload_ = CHAR_IP_HDR_PTR_TP_PAYLOAD(ip_hdr);
  if(strncmp(ip, IP_HOST_MULTICAST_ADDR, IP_LENGTH) == 0) {
 
    //promote this to layer 5
    char *payload = CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr);
    payload_size = IP_HDR_PAYLOAD_SIZE(ip_hdr);
    //수정 : 지금 foreign network 에서 받은거기때문에 mk_router_discovery_msg를 요따 넣어야댐
    switch(*payload){
      case ICMP_ROUTER_SOLICITATION: {
        // ip_add_t src_ip;
        // ip_addr_n_to_p(ip_hdr->src_ip, src_ip.ip_addr);

        // printf("hello router solic src  %s\n", node->name);
        // // add_route_entry(node, src_ip.ip_addr, 32, "79.119.42.3", recv_intf->name, 1);
        // add_route_entry(node, "128.119.40.186", 32, "79.119.42.3", recv_intf->name, 1);
        // sleep(2);
        // rt_entry_t *test = lookup_rt_table(node, ip_hdr->src_ip);
        // printf("test oif %s\n", test->oif);
        process_router_solicitation_request(node, ip_hdr->src_ip);
        //free ?
        // free(payload);
        return;
      }
      default :return;
    }
    // promote_pkt_to_l5(node, recv_intf, payload, payload_size-IP_HDR_LEN_IN_BYTES(ip_hdr), ICMP);
    // if ICMP, and type 10 , make discovery msg and send it back to src ip
  }

  //rt table lookup 
  rt_entry_t *rt_entry = lookup_rt_table(node, ip_hdr->dest_ip);
  //if no result, discard
  if(rt_entry == NULL) {
    printf("no such ip : %s in router %s\n", ip, node->name);
    return;
  }
  //printf("rt entry : %s, is direct : %d, proto : %d\n", rt_entry->dest_ip, rt_entry->is_direct == TRUE, ip_hdr->protocol);
  


  //if matched 
  int nxt_idx = ret_nxthop_idx(rt_entry);
  interface_t *matched_intf = rt_entry->nxt_hops[nxt_idx]->oif;
  // interface_t *matched_intf = get_node_if_by_name(node, rt_entry->oif);
  // 
  // if belongs to local subnet
  if(rt_entry->is_direct == TRUE){
    // #1 local delivery : if exact match  
    if(is_exact_match(node, ip) == TRUE || strncmp(NODE_LO_ADDR(node), ip, IP_LENGTH) == 0) {
      switch(ip_hdr->protocol) {
        case ICMP: {
          // promote pkt to layer 5
          char *ip_hdr_payload = CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr);
          // *payload refers to the type of ICMP message
          switch(*ip_hdr_payload) {
            case ICMP_ECHO_REPLY: {
              promote_pkt_to_l5(node, recv_intf, ip_hdr_payload, payload_size-IP_HDR_LEN_IN_BYTES(ip_hdr), ICMP);
              return;
            }
            case ICMP_ECHO_REQUEST: {
              process_icmp_echo_request(node, payload, recv_intf, payload_size);
              //make IP header pkt
              // free(payload);
              return;
            }
            case ICMP_ROUTER_DISCOVERY: {
              process_router_discovery_request(node, payload, recv_intf, payload_size);
              return;
            }

            default: return;
          }
        }
        case UDP: {
          char *ip_hdr_payload = CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr);
          
          promote_pkt_to_l4(node, recv_intf, ip_hdr_payload, payload_size-sizeof(ip_hdr_t), UDP);
          return;
        }
        case IP_IN_IP: {
          if(node->node_nw_props.is_foreign_agent == TRUE) {
            char *iii_payload = CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr);
            l3_rcv_ip_frame_from_bottom(node, recv_intf, iii_payload, ETH_IP, payload_size - IP_HDR_LEN_IN_BYTES(ip_hdr));
            return;
          } 
          else {
            printf("undefined behavior \n");
            return;
          }
        }
        default : return;
      }
    }
    // check if this pkt is for coa configured one
    if(rt_entry->is_coa_configured == TRUE) {
      // get the payload and append it with IP_IN_IP header,
      demote_pkt_to_l3(node, payload, payload_size, IP_IN_IP, ip_addr_p_to_n(rt_entry->coa.ip_addr));
      return;
    }
    // #2 if just a subnet match : send it to local subnet , so no gw_ip, just outgoing interface would be passed
    else {
      if(rt_entry->is_svi_configured == TRUE) {
        //for svi, specify nexthop
        demote_pkt_to_l2(node, ip_hdr->dest_ip, payload, payload_size, matched_intf->name, ETH_IP, rt_entry->svi_vlan_id);
        // demote_pkt_to_l2(node, ip_hdr->dest_ip, payload, payload_size, rt_entry->oif, ETH_IP, rt_entry->svi_vlan_id);
        return;
      }
     
      demote_pkt_to_l2(node, 0, payload, payload_size, matched_intf, ETH_IP, 0);
      // demote_pkt_to_l2(node, 0, payload, payload_size, rt_entry->oif, ETH_IP, 0);
      return;
    }
  } else {
    
    //if not matched , decrease ttl field , forward the pck (demote down to L2)
    ip_hdr->ttl--;
    if(ip_hdr->ttl == 0) {
      // clear matching routing table entry
      return;
    }
    demote_pkt_to_l2(node, ip_addr_p_to_n(rt_entry->nxt_hops[nxt_idx]->gw_ip), payload, payload_size, matched_intf, ETH_IP, 0);
    // demote_pkt_to_l2(node, ip_addr_p_to_n(rt_entry->gw_ip), payload, payload_size, rt_entry->oif, ETH_IP, 0);
    return;
  }

};

void promote_pkt_to_l3(node_t *node, interface_t *recv_intf, char *payload, int protocol_number, unsigned int payload_size){
   switch(protocol_number){
     case ETH_IP: {

       l3_rcv_ip_frame_from_bottom(node, recv_intf, payload, protocol_number, payload_size);
       return;
     }
     default: break;
   }
};

static void mk_ip_registration_request_pkt_from_ip_pkt(node_t *node, interface_t *recv_intf, unsigned int dest_ip, char *payload, unsigned int *payload_size){
  mbl_ip_register_req_msg_t * reg_msg = (mbl_ip_register_req_msg_t *)payload;
  reg_msg->type = MOBILE_IP_REGISTRATION_REQUEST;
  reg_msg->M = 0;
  reg_msg->B = 0;
  reg_msg->G = 0;
  reg_msg->D = 0;
  reg_msg->T = 0;
  reg_msg->S = 0;
  reg_msg->r = 0;
  reg_msg->x = 0;
  reg_msg->identification = 0;
  reg_msg->lifetime = 0;
  // reg_msg->home_addr = ip_addr_p_to_n(recv_intf->intf_nw_props.ip_add.ip_addr);
  reg_msg->home_addr = ip_addr_p_to_n(NODE_LO_ADDR(node));
  reg_msg->home_agent_addr = ip_addr_p_to_n(node->node_nw_props.home_agent_addr.ip_addr);
  //I defined 'coa' here : network address of foreign agent's interface
  // reg_msg->coa = dest_ip;
  reg_msg->coa = ip_addr_p_to_n(node->node_nw_props.router_address.ip_addr);
  *payload_size += sizeof(mbl_ip_register_req_msg_t);
}

void process_router_discovery_request(node_t *node, char *payload, interface_t *recv_intf, unsigned int payload_size) {
  // if ICMP message coming up here, it should be registration message

  // after calculating router address that it received, (based on priority), set best router interface and set it as a coa
  router_discovery_basic_msg_t *disc_msg = (router_discovery_basic_msg_t *)(payload + sizeof(ip_hdr_t));
  uint32_t max_pref_level = 0;
  uint32_t max_ip;

  char num_addrs = disc_msg->num_addrs;
  for(int i=0; i < num_addrs; i++){
    router_discovery_entry_t *entry = (router_discovery_entry_t *)((char *)disc_msg+sizeof(router_discovery_basic_msg_t)+i*sizeof(router_discovery_entry_t));
    if(entry->preference_level >= max_pref_level){
      max_pref_level = entry->preference_level;
      max_ip = entry->router_addr;
      char test[16];
      ip_addr_n_to_p(max_ip, test);
    }
  }
  // mobile node
  ip_addr_n_to_p(max_ip, node->node_nw_props.router_address.ip_addr);
  node->node_nw_props.router_pref_level = max_pref_level;
  // printf("router address : %s\n", node->node_nw_props.router_address.ip_addr);
  // add_route_entry(node, node->node_nw_props.router_address.ip_addr, recv_intf->intf_nw_props.mask, 0, recv_intf->name, 1);

  char *new_payload = (char *)calloc(1, MAX_BUF_SIZE);
  unsigned int new_payload_size = 0;
  mk_ip_registration_request_pkt_from_ip_pkt(node, recv_intf,((ip_hdr_t *)payload)->src_ip, new_payload, &new_payload_size);
  
  memmove(new_payload+MAX_BUF_SIZE-new_payload_size, new_payload, new_payload_size);

  new_payload = new_payload + MAX_BUF_SIZE - new_payload_size;
  
  // printf("type : %d, new_payload_size : %d \n", ((mbl_ip_register_msg_t *)new_payload)->type, new_payload_size);
  promote_pkt_to_l4(node, recv_intf, new_payload, new_payload_size, ICMP);
      // but how about router's link ? we've already established the link between router and mobile node. 
      // read how does the link finally established RFC1256
      // 1. 이 인터페이스에 맞는 메시지, 2. preference level
      // 연결 router address, preference level 을 유지한다. 
      // pending list 에 올리고 (register msg. 를 받는 즉시 등록한다.)
      // register msg 를 보낸다. 홈 어드레스를 도착지점으로, 라우터 어드레스를 next hop으로 지정해서 보낸다. 이 인터페이스의 ip가 소스 ip이다.

      // 그 후(논리 불확실) foreign 라우터에서 받고, 타입 확인(protocol UDP , + switch(type)) 후에 udp면 올라와서 request 면 역시 펜딩리스트에 이 모바일 노드를 등록하고, 홈에이전트로 다시 보낸다. 그 후 홈에이전트에서 올바른 메시지가 오면 다시 등록한다. 그리고 모바일 노드에게 등록응답을 또 보낸다. 

      //홈 에이전트는 받는다면( 434 포트로 받는 것 시뮬레이션 )(request 이고 dest 가 같음) 정확성 검사하고, 따로 테이블에 이 바인딩 정보를 유지할 수 있게 데이터 스트럭쳐를 만들어서 관리한다. 그후 reply 메세지를 모바일노드를 dest 로 설정하여 다시 보낸다. 그 후 이 아이피에 대한 요청이 들어왔을때 IP_in_IP 터널링을 모델링 한다.

      // 다 한후 따로 테스팅api를 만들어서 모바일 노드가 이동(다른 라우터에 연결됨)을 가정해 역시 같은 과정을 반복해 바인딩 정보를 갱신하고 sender 측에서 request 를 보냈을때 올바르게 도착하는지 테스트한다.

  // go up to the transport layer (layer4 )and make registration message using UDP
 
}

void process_router_solicitation_request(node_t *node, uint32_t dest_ip){
  char *new_payload = (char *)calloc(1, MAX_BUF_SIZE);
  unsigned int payload_size = 0;
  mk_router_discovery_msg(node, new_payload, &payload_size);
  //problem
  printf("processing router solicitation\n");
  demote_pkt_to_l3(node, new_payload, payload_size, ICMP, dest_ip);
  return;
  //free payload ?
  // free(payload);
};

void mk_router_discovery_msg(node_t *node, char *new_payload, unsigned int *payload_size){
  // make discovery msg and send it back
  // check available interface and send all the addresses that are available to src ip
  router_discovery_basic_msg_t *msg = (router_discovery_basic_msg_t *)new_payload;
  msg->type = ICMP_ROUTER_DISCOVERY;
  msg->code = 0;
  msg->checksum = 0;
  msg->num_addrs = 0;
  msg->addr_entry_size = 0;
  msg->lifetime = 3000;
  new_payload += sizeof(router_discovery_basic_msg_t);
  *payload_size += sizeof(router_discovery_basic_msg_t);
  //find available router address
  //if found, append to the msg
  int until = get_node_intf_available_slot(node);

  for(int i=0; i< until; i++) {
    if(node->if_list[i]->intf_nw_props.advertise == 0) continue;
    router_discovery_entry_t *entry = (router_discovery_entry_t *)(new_payload);
    entry->preference_level = node->if_list[i]->intf_nw_props.preference_level;
  
    entry->router_addr = ip_addr_p_to_n(node->if_list[i]->intf_nw_props.ip_add.ip_addr);
    msg->num_addrs += 1;
    msg->addr_entry_size += 2;
    //move ptr to the end
    new_payload += sizeof(router_discovery_entry_t);
    *payload_size += sizeof(router_discovery_entry_t);
  }
  // 앞에 공간 확보, 끝으로 옮김
  memmove((char *)msg + MAX_BUF_SIZE - *payload_size, (char *)msg, *payload_size);
  new_payload = (char *)msg + MAX_BUF_SIZE - *payload_size;
  // printf("lifetime : %d\n",((router_discovery_basic_msg_t *)new_payload)->lifetime);
  return;
  //set ip header
 
}
//could make several solicit msgs if there are another routers near mobile node

void mk_router_solicit_msg(node_t *mobile_node){
  char *payload = (char *)calloc(1, MAX_BUF_SIZE);
  
  router_solicit_msg_t sol_msg;
  sol_msg.code = 0;
  sol_msg.reserved = 0;
  sol_msg.type = 10; // type 10 for solicit ICMP
  sol_msg.checksum = 0;

  payload = payload + MAX_BUF_SIZE - sizeof(router_solicit_msg_t);
  memcpy(payload, &sol_msg, sizeof(router_solicit_msg_t));
  unsigned int data_size = sizeof(router_solicit_msg_t);

// this multicast address should be revised to solicit address inside of each node
  demote_pkt_to_l3(mobile_node, payload, data_size, ICMP, ip_addr_p_to_n(mobile_node->node_nw_props.solicit_addr.ip_addr));
};

void mk_ping_echo_msg(node_t *host_node, char *payload, unsigned int *msg_size, char echo_msg_type){
  // in payload, the space is allocated and assuming the ptr is pointing to the starting point and we just append the payload from there
  ICMP_ping_msg_t *echo_msg = (ICMP_ping_msg_t *)payload;
  echo_msg->checksum = 0;
  echo_msg->code = 0;
  echo_msg->type = echo_msg_type;
  echo_msg->sequence_num = 0;
  echo_msg->identifier = 0;
  *msg_size += sizeof(ICMP_ping_msg_t);
  // set the entries inside of msg
};

static void process_icmp_echo_request(node_t *node, char *recvd_ip_header, interface_t *recvd_intf,unsigned int payload_size) {
  // should check and return the message with ICMP_ECHO_REPLY
  ip_hdr_t *ip_hdr = (ip_hdr_t *)recvd_ip_header;
  char* payload = CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr);

  ICMP_ping_msg_t *echo_req = (ICMP_ping_msg_t *)payload;
  payload_size = payload_size-IP_HDR_LEN_IN_BYTES(ip_hdr);
  //check all the fields like sequence num, identifier, code, checksum
  assert(echo_req->code == 0 && echo_req->checksum == 0);
  char *ping_payload = ICMP_ECHO_MSG_PTR_TO_PAYLOAD(echo_req);
  //this payload_size is the size of actual ping payload
  payload_size -= sizeof(ICMP_ping_msg_t);

  //making new payload
  char *new_payload = (char *)calloc(1, MAX_BUF_SIZE);
  //msg_size would be the size of icmp echo reply msg
  unsigned int msg_size = 0;
  mk_ping_echo_msg(node, new_payload, &msg_size, ICMP_ECHO_REPLY);
  //copying the existing payload
  memcpy(new_payload + msg_size, ping_payload, payload_size);
  msg_size += payload_size;
  //shift the packet to the end of buffer
  new_payload = new_payload + MAX_BUF_SIZE - msg_size;
  // appending ip header
  demote_pkt_to_l3(node, new_payload, msg_size, ICMP, ip_hdr->src_ip);
}

// process registration msg based on 1. if this node is home agent
// 2. if this node is foreign agent
// and set dest ip based on that
void process_ip_registration_request(node_t *node, char **payload, unsigned int *payload_size, interface_t *recv_intf, uint32_t *dest_ip, char *is_home_agent){
  mbl_ip_register_req_msg_t *reg_msg = (mbl_ip_register_req_msg_t *)*payload;
  printf("processing ip registration request\n");
  int until = get_node_intf_available_slot(node);
  for(int i=0; i< until; i++){
    if(reg_msg->home_agent_addr == ip_addr_p_to_n(node->if_list[i]->intf_nw_props.ip_add.ip_addr)) {
      //this is home agent 
      *is_home_agent = 1;
    }
  }
  if(*is_home_agent) {
    // register this address to HLR , mobile ip will already be enrolled in the home network's route table
    // validity and all those procedure should include here
    rt_entry_t *mobile_entry = lookup_rt_table(node, reg_msg->home_addr);
    int nxt_idx = ret_nxthop_idx(mobile_entry);
    if(mobile_entry == NULL) {
      printf("mobile ip not enrolled to the home network\n");
      return;
    }
    mobile_entry->is_coa_configured = TRUE;
    ip_addr_n_to_p(reg_msg->coa, mobile_entry->coa.ip_addr);
    memcpy(mobile_entry->nxt_hops[nxt_idx]->oif->name, recv_intf->name, IF_NAME_SIZE);
    // memcpy(mobile_entry->oif, recv_intf->name, IF_NAME_SIZE);
    
    *dest_ip = reg_msg->coa;
    uint32_t home_addr = reg_msg->home_addr;
    uint32_t home_agent_addr = reg_msg->home_agent_addr;
    // registration reply 
    *payload += sizeof(mbl_ip_register_req_msg_t);
    *payload_size -= sizeof(mbl_ip_register_req_msg_t);
    *payload -= sizeof(mbl_ip_register_reply_msg_t);
    *payload_size += sizeof(mbl_ip_register_reply_msg_t);

    mbl_ip_register_reply_msg_t *reply_msg = (mbl_ip_register_reply_msg_t *)*payload;
    
    reply_msg->type = MOBILE_IP_REGISTRATION_REPLY;
    reply_msg->code = 0;
    reply_msg->lifetime = 0;
    reply_msg->home_addr = home_addr;
    reply_msg->home_agent_addr = home_agent_addr;
    reply_msg->identification = 0;
    return;
  } else {
    // add the info to the coa-mobile node mapping. if reply message fails => delete it (so just add it here)
    node->node_nw_props.is_foreign_agent = TRUE;
    ip_addr_n_to_p(reg_msg->home_addr, node->node_nw_props.mobile_node_ip.ip_addr);
    ip_addr_n_to_p(reg_msg->coa, node->node_nw_props.coa.ip_addr);
    //forward to home agent
    //printf("forwarding to home agent\n");
    *dest_ip = reg_msg->home_agent_addr;
    return;
  }
}

void process_ip_register_reply_request(node_t *node, char *payload, interface_t *recv_intf, uint32_t *dest_ip) {
  // if foreign agent or not
  mbl_ip_register_reply_msg_t *reg_msg = (mbl_ip_register_reply_msg_t *)payload; 
  // if mobile node
  if(node->node_nw_props.is_lb_addr == TRUE && reg_msg->home_addr == ip_addr_p_to_n(NODE_LO_ADDR(node))) {
  // if reply message has failed : delete the router address and try for other one
    // just simple implementation : if code is not 0 (all success), then failed
    if(reg_msg->code != 0) {
      memset(node->node_nw_props.router_address.ip_addr, 0, IP_LENGTH);
      node->node_nw_props.router_pref_level = 0; // default : 0
    }
    *dest_ip = 0;
    return;
  }; // i think we should change it to loopback address
  // if foreign agent
  // if reply message is failed : delete the coa and mobile ip mapping entry
  if(reg_msg->code != 0) {
    node->node_nw_props.is_foreign_agent = FALSE;
    memset(node->node_nw_props.coa.ip_addr, 0, IP_LENGTH);
    memset(node->node_nw_props.mobile_node_ip.ip_addr, 0, IP_LENGTH);
  }
  // forward it to mobile ip
  
  *dest_ip = ip_addr_p_to_n(node->node_nw_props.mobile_node_ip.ip_addr);

  return;
  // return
}

void set_default_gw_ip(node_t *node, char *ip_addr, unsigned int cost){
  strncpy(node->node_nw_props.default_gw.ip_addr, ip_addr, IP_LENGTH);
  // rt_entry_t *default_gw = add_route_entry(node, "0.0.0.0", mask, ip_addr, oif, cost); 
  rt_entry_t *default_gw = lookup_rt_table(node, ip_addr_p_to_n(ip_addr));
  // printf("gw ip ip ip : %s\n", default_gw->gw_ip);
  memcpy(default_gw->nxt_hops[0]->gw_ip, ip_addr, IP_LENGTH);
  // memcpy(default_gw->gw_ip, ip_addr, IP_LENGTH);
  return;
};

interface_t *get_trunk_intf(node_t *node){
  int until = get_node_intf_available_slot(node);
  for(int i=0; i<until; i++){
    if(node->if_list[i]->intf_nw_props.l2_mode == TRUNK) {
      return node->if_list[i];
    }
  }
  return NULL;
}


void bind_ip_with_vlan(node_t *node, unsigned int vlan_id, char *ip_addr, char mask, unsigned int cost){
  interface_t *oif;
  //for both interface, and route table configure svi
  if((oif = get_trunk_intf(node)) == NULL) {
    printf("no interface configured with TRUNK mode\n");
    return;
  }
  oif->intf_nw_props.mask = mask;
  // find matching location
  for(int i=0; ; i++){
    if(oif->intf_nw_props.vlan_id[i] == vlan_id) {
      memcpy(oif->intf_nw_props.vlan_id_binded_ip[i].ip_addr, ip_addr, IP_LENGTH);
      break;
    } 
  }
  oif->intf_nw_props.is_svi_config = TRUE;
  rt_entry_t *rt_entry = add_route_entry(node, ip_addr, mask, NULL, oif, 1);
  // rt_entry_t *rt_entry = add_route_entry(node, ip_addr, mask, NULL, oif->name, 1);
  rt_entry->is_svi_configured = TRUE;
  rt_entry->svi_vlan_id = vlan_id;
};
