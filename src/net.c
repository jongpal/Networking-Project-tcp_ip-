#include "../include/hash.h"
#include "../include/utils.h"
#include "../include/graph.h"
#include <assert.h>
extern void config_node_udp_props(node_t* node);
extern void init_route_table(node_t *node);
// extern void dump_rt_table(node_t *node);
extern rt_entry_t* add_route_entry(node_t *router, char *dst, char mask, char *gw, interface_t *oif, unsigned char cost);
// extern void add_route_entry(node_t *rt, char *dst_ip, char mask, char *gw_ip, char*oif);

unsigned char* generate_mac(char *node_name, char *intf_name);

// bool_t IS_IF_UP(interface_t *intf){
//   return (intf->intf_nw_props.if_up == TRUE) ? TRUE : FALSE;
// } 

void convert_ip_from_int_to_str(unsigned int ip_addr, char *output_buffer){
  inet_ntop(AF_INET, &ip_addr, output_buffer, PREFIX_LEN);
};
unsigned int convert_ip_from_str_to_int(char *ip_addr){
  unsigned int int_ip;
  inet_pton(AF_INET, ip_addr, &int_ip); 
  return int_ip;
};

void init_intf_nw_props(intf_nw_props_t *intf_nw_props){
  memset(intf_nw_props -> mac_add.mac_addr, 0, 6);
  intf_nw_props -> is_ip_config = FALSE;
  memset(intf_nw_props -> ip_add.ip_addr, 0, 16);
  intf_nw_props->l2_mode = UNDEFINED;
  intf_nw_props->advertise = 0;
  intf_nw_props->preference_level = 0;
  intf_nw_props->if_up = TRUE;
  // intf_nw_props->port_type = UNDEF;
  intf_nw_props->is_svi_config = FALSE;
}

void init_node_nw_props(node_t *node) {

  // node_nw_props->is_root_switch = FALSE;
  //base mac
  unsigned char *mac = generate_mac(node->name, "intf");
  memcpy(node->node_nw_props.base_mac.mac_addr, mac, MAC_LENGTH);
  // node->node_nw_props.stp_infos.path_cost_to_root = 0;
  // bid_t *bid = (bid_t *)calloc(1, sizeof(bid_t));
  
  // // bid->vlan_number = 
  // node->node_nw_props.stp_infos.loc_rootid = 
  // node->node_nw_props.stp_infos.self_bid
  node->node_nw_props.is_lb_addr = FALSE;
  memset(node->node_nw_props.lb_add.ip_addr, 0, IP_LENGTH);

  init_arp_table(node);
  init_mac_table(node);
  init_route_table(node);
  config_node_udp_props(node);
}

void set_node_spt_mode(node_t *node){
  int until = get_node_intf_available_slot(node); 
  unsigned int vlan_list[MAX_VLAN_CONFIG];
  
  int k = 0;
  for(int i=0;i < until;i++) {
    char is_exist = 0;
    if(node->if_list[i]->intf_nw_props.l2_mode == ACCESS) {
      for(int j=0; j< k+1; j++) {
        if(vlan_list[j] == node->if_list[i]->intf_nw_props.vlan_id[0]) {
          is_exist = 1;
        }
      }
      if(!is_exist) {
        vlan_list[k] = node->if_list[i]->intf_nw_props.vlan_id[0];
        k++;
      }

    } else if(node->if_list[i]->intf_nw_props.l2_mode == TRUNK) {
      int n =0;
      while(node->if_list[i]->intf_nw_props.vlan_id[n] != 0){
        for (int j=0; j < k+1; j++) {
          if(vlan_list[j] == node->if_list[i]->intf_nw_props.vlan_id[n]) {
            is_exist = 1;
          }
        }
        if(!is_exist) {
          vlan_list[k] = node->if_list[i]->intf_nw_props.vlan_id[n];
          k++;
        }
        n++;
      }
    }
  }
  //vlan 별 할당
  for(int i=0; i < k; i++){
    node->node_nw_props.stp_infos[i].self_bid.bridge_priority = 0b1000; // default : 32768
    node->node_nw_props.stp_infos[i].self_bid.vlan_number = vlan_list[i]; 
    memcpy(node->node_nw_props.stp_infos[i].self_bid.mac, node->node_nw_props.base_mac.mac_addr, MAC_LENGTH);
  }
  //for(int i = 0; i < k; i++)
  //  printf("i : %d\n", vlan_list[i]);
};

interface_t* node_get_matching_subnet_interface(node_t *node, char *ip_addr){
  int until = get_node_intf_available_slot(node);
  if(until == 0) return NULL;
  char output[PREFIX_LEN];
  char ori_output[PREFIX_LEN];

  for(int i = 0 ; i < until; i++){
    apply_mask(ip_addr, node->if_list[i]->intf_nw_props.mask, output);
    apply_mask(IF_IP(node->if_list[i]), node->if_list[i]->intf_nw_props.mask, ori_output);
    if(!strncmp(output, ori_output, PREFIX_LEN)){
      return node->if_list[i];
    };
  }
  return NULL;
};

bool_t node_set_loopback_address(node_t *node, char *ip_addr){
  if(node == NULL) {
    printf("err : node not exists \n");
    return FALSE;
  }
  // init_node_nw_props(&node->node_nw_props);
  strncpy(NODE_LO_ADDR(node), ip_addr, 16);
  node->node_nw_props.is_lb_addr = TRUE;
  //add direct routes(local subnet) to routing table
  //this should be done as soon as lb address is configured
  add_route_entry(node, ip_addr, 32, NULL, NULL, 0);
  // add_route_entry(node, ip_addr, 32, NULL, NULL);

  return TRUE;
};
bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask){
  interface_t *found_if = get_node_if_by_name(node, local_if);
  if(node == NULL || found_if == NULL) {
    printf("node or interface not exist\n");
    return FALSE;
  }
  strncpy(IF_IP(found_if), ip_addr, IP_LENGTH);
  found_if-> intf_nw_props.mask = mask;
  found_if-> intf_nw_props.is_ip_config = TRUE;

  // dump_rt_table(node);
  add_route_entry(node, ip_addr, mask, NULL, found_if, 0);
  // add_route_entry(node, ip_addr, mask, NULL, local_if);
  
  return TRUE;
};
// 
void node_intf_set_l2_mode(node_t *node, char *intf_name, l2_mode_t mode){
  interface_t *intf = get_node_if_by_name(node, intf_name);
  // if ip is configured, simply erase it and set it to l2 mode
  if(intf->intf_nw_props.is_ip_config == TRUE) {
    intf->intf_nw_props.is_ip_config = FALSE;
  };
  intf->intf_nw_props.l2_mode = mode;
   //erase vlan id configured : should be reconfigured again

  for(int i=0; i < MAX_VLAN_CONFIG; i++) {
    intf->intf_nw_props.vlan_id[i] = 0;
  }
};
void node_intf_set_vlanid(node_t *node, char *intf_name, unsigned int vlan_id) {
  interface_t *intf = get_node_if_by_name(node, intf_name);  
  if(IS_INTF_L3_MODE(intf) == TRUE || intf->intf_nw_props.l2_mode == UNDEFINED) {
    printf("intf not configured with l2 mode\n");
    return;
  }
  if(intf->intf_nw_props.l2_mode == ACCESS) {
    if(intf->intf_nw_props.vlan_id[0]) {
      printf("vlan id already configured in access mode\n");
      return;
    }
    intf->intf_nw_props.vlan_id[0] = vlan_id;
    return;
  }
  else if(intf->intf_nw_props.l2_mode == TRUNK) {
    
    for(int i = 0; i < MAX_VLAN_CONFIG; i++) {
      if(intf->intf_nw_props.vlan_id[i] == 0){
        intf->intf_nw_props.vlan_id[i] = vlan_id;
        return;
      }
    }
    printf("all available vlan id is occupied already \n");
    return;
  }
}

char *get_string_from_l2_mode(l2_mode_t l2_mode){
  switch(l2_mode){
    case ACCESS:
      return "access";
    case TRUNK:
      return "trunk";
    case UNDEFINED:
      return "undefined";
  }
};
bool_t node_unset_intf_ip_address(node_t *node, char *local_if){
  interface_t *found_if = get_node_if_by_name(node, local_if);
  if(node == NULL || found_if == NULL) {
    printf("node or interface not exist\n");
    return FALSE;
  }
  memset(IF_IP(found_if), 0, 16);
  return TRUE;
};


// just generate random mac using distinct node/intf name
unsigned char* generate_mac(char *node_name, char *intf_name){
  static unsigned char mac[MAC_LENGTH];
  //첫 2 바이트는 node_name, 뒤에 2바이트는 intf_name 
  char first_three[3] = {0xff, 0xff, 0xff};
  char second_three[3] = {0xff, 0xff, 0xff};

  int j = 0;
  for(int i = 0 ; i < strlen(node_name); i++){
    if(j >= 3 ) j = 0;

    first_three[j] -= node_name[i];

    if(first_three[j] < 0) {
      first_three[j] = first_three[j] & 0x000000ff;
    }
    j++;
  }
  
  j = 0;
  for(int i = 0 ; i < strlen(intf_name); i++){
    if(j >= 3 ) j = 0;
    second_three[j] -= intf_name[i];
    if(second_three[j] < 0) second_three[j] = second_three[j] & 0x000000ff;
    j++;
  }

  int k = 3;
  for(int i = 0 ; i < 3; i++){
    mac[i] = first_three[i];
    mac[k] = second_three[i];
    k++;
  }
  return mac;
}

void interface_assign_mac_address (interface_t *interface){
  node_t *node = interface->node;
  unsigned char *mac_addr = generate_mac(node->name, interface->name);
  // strncpy(IF_MAC(interface), mac_addr, MAC_LENGTH);
  memcpy(IF_MAC(interface), mac_addr, MAC_LENGTH); 
};

// freeing graph
// void free_nw_graph(void* graph, enum type t){
//   switch(t){
//     case G_E_T:{
//       int size = ((graph_t*)graph)->curr_size;
//       graph_elements_t* cur = ((graph_t*)graph)->hash_graph;
//       int i = 0;
//       while(i < size){
//         if(cur->is_entry) {
//           // printf("freeing : %s\n", cur->node->name);
//           i++;
//           free(cur->entry);
//         }
//         cur++;
//       };
//       free(((graph_t*)graph)->hash_graph);
//       free(graph); 
//     }
//     break;
//     case A_E_T :{
      // int size = ((ctrl_arp_table_t*)graph)->curr_size;
      // arp_table_t* cur = ((ctrl_arp_table_t*)graph)->arp_table;
      // int i = 0;
      // while(i < size){
      //   if(cur->is_entry) {
      //     // printf("freeing : %s\n", cur->node->name);
      //     i++;
      //     free(cur->entry);
      //   }
      //   cur++;
      // };
      // free(((ctrl_arp_table_t*)graph)->arp_table);
      // free(graph); 
//     }
//     break;
//     default: break;
//   }
// };
void free_nw_graph(ctrl_table_t* graph){
  int size = graph->curr_size;

  // graph_elements_t* cur = graph->hash_graph;
  graph_elements_t* cur = graph->table_ptr;
  int i = 0;
  while(i < size){
    if(cur->is_entry) {
      // printf("freeing : %s\n", cur->node->name);
      i++;
      free(cur->entry);
    }
    cur++;
  };
  // free(graph->hash_graph);
  free(graph->table_ptr);
  free(graph); 
};

void dump_intf_nw_props(interface_t* intf){
  interface_t *nbr;
  printf("\n");
  printf("Interface of %s, name : %s ---\n", intf->node->name, intf->name);
  printf("IS UP : %s\n", intf->intf_nw_props.if_up == TRUE ? "TRUE" : "FALSE");
  printf("Mac address : ");
  for(int i = 0 ; i < MAC_LENGTH; i++) {
    if(i != 0) printf(":");
    printf("%x", intf->intf_nw_props.mac_add.mac_addr[i]);
  }
  printf("\n");
  if(intf->intf_nw_props.is_ip_config == TRUE) {
    printf("IP address : %s\n", IF_IP(intf));
    printf("Mask value : %d\n", intf->intf_nw_props.mask);
  } else {
    printf("interface IP address not configured\n");
    l2_mode_t mode = intf->intf_nw_props.l2_mode;
    if(mode == ACCESS || mode == TRUNK){
      switch(mode){
        case UNDEFINED:{
          printf("Interface l2 mode not configured\n");
        }
        case ACCESS:{
          printf("ACCESS mode, vlan id : %d\n", intf->intf_nw_props.vlan_id[0]);
          break;
        }
        case TRUNK:{
          // printf("\n");
          int k=0;
          unsigned int *vlan_id = intf->intf_nw_props.vlan_id;

          while(vlan_id[k] != 0) {
            if(vlan_id[k]) {
              printf("TRUNK mode, vlan id : %d\n", vlan_id[k]);
            }
            k++;
          }
          break;
        }
      }
    }
    
  }
  if((nbr = get_nbr_node_intf(intf)) != NULL) {
    printf("Neighbor node name : %s\n", nbr->node->name);
  }
}

void dump_node_props(node_t* node){
  printf("--------\n");
  printf("Node name: %s\n", node->name);
  printf("base mac : ");
  for(int k=0; k < MAC_LENGTH; k++) {
    printf("%x:", node->node_nw_props.base_mac.mac_addr[k]);
  }
  printf("\n");
  if(node->node_nw_props.is_lb_addr == TRUE) {
    printf("Node loop back address : %s\n", NODE_LO_ADDR(node));
  } else {
    printf("Node loopback address not configured \n");
  }
  int i = 0;
  while(node->node_nw_props.stp_infos[i].self_bid.vlan_number != 0 && i <= MAX_VLAN_CONFIG){
    if(node->node_nw_props.stp_infos[i].self_bid.vlan_number) {
      printf("switch spt configured, self bridge id : %d.%d.", node->node_nw_props.stp_infos[i].self_bid.bridge_priority*4096, node->node_nw_props.stp_infos[i].self_bid.vlan_number);
      for(int j = 0; j< MAC_LENGTH; j++) {
        printf("%x:", node->node_nw_props.stp_infos[i].self_bid.mac[j]);
      }
      printf("\n");
    }
    i++;
  }
}

void dump_node_nw_props(node_t *node){
  int until = get_node_intf_available_slot(node);
  dump_node_props(node);
  for(int i = 0 ; i < until; i++) {
    dump_intf_nw_props(node->if_list[i]);
  }
}

void dump_nw_graph(ctrl_table_t* graph) {
  
  int size = graph->curr_size;
  // graph_elements_t* cur = graph->hash_graph;
  graph_elements_t* cur = graph->table_ptr;
  int i = 0;
  while(i < size) {
    if(cur->is_entry) {
      i++;
      dump_node_nw_props(cur->entry);
    }
    cur++;
    printf("\n");
  }
}

//static
void parse(char *s2, char *ip_parsed[]){
  char *ret_ptr;
  char *next_ptr;

  ret_ptr = strtok_r(s2, ".", &next_ptr);
  int cur = 0;

  while(ret_ptr) {
    ip_parsed[cur] = ret_ptr;
    ret_ptr = strtok_r(NULL, ".", &next_ptr);
    cur++;
  }
}


//return in network byte order
unsigned int ip_addr_p_to_n(char *ip_addr) {
  char *s1 = malloc(sizeof(char)*PREFIX_LEN);
  strncpy(s1, ip_addr, strlen(ip_addr)+1);

  char *ip_parsed[4];
  parse(s1, ip_parsed);

  unsigned int to_int = 0;
  for(int i = 0; i < 4; i++) {
    to_int += atoi(ip_parsed[i]) << (32 - 8*(i+1));
  }
  free(s1);
  return htonl(to_int);
};


void ip_addr_n_to_p(unsigned int ip_addr, char* ip_add_str){
  unsigned int ip_int = ntohl(ip_addr);
  int sum[4]= {0,};
  for(int i = 31; i >= 0; i--) {
    int where;
    if(i <= 31 && i >=24) where = 0;
    else if( i <=23 && i >= 16) where = 1;
    else if(i <= 15 && i >= 8) where = 2;
    else where = 3;
    unsigned int x = 1 << i;

    if(i == 31 && ip_int >= x) {
      sum[0] += x >> (24 - where*8);
      ip_int -= x;
    }
    else if(ip_int >= x && ip_int < (x << 1)){
      sum[where] += x >> (24 - where*8);
      ip_int -= x;
    }
  }

  sprintf(ip_add_str,"%d.%d.%d.%d", sum[0],sum[1],sum[2],sum[3]);
};


bool_t is_interface_l3_bidirectional(interface_t *interface){
  // both side of interface should be exist & up
  interface_t* nbr_intf = get_nbr_node_intf(interface);
  if(nbr_intf == NULL) return FALSE ;
  if(IS_IF_UP(nbr_intf) == FALSE || IS_IF_UP(interface) == FALSE) return FALSE;
  // both side of interface should be configured with IP addresses
  if(interface->intf_nw_props.l2_mode == ACCESS || interface->intf_nw_props.l2_mode == TRUNK || nbr_intf->intf_nw_props.l2_mode == ACCESS || nbr_intf->intf_nw_props.l2_mode == TRUNK) return FALSE;

  if(interface->intf_nw_props.is_ip_config == FALSE && nbr_intf->intf_nw_props.is_ip_config == FALSE) return FALSE;
  char intf_masked[IP_LENGTH];
  char nbr_masked[IP_LENGTH];

  // in same subnet
  apply_mask(interface->intf_nw_props.ip_add.ip_addr, interface->intf_nw_props.mask,intf_masked );
  apply_mask(nbr_intf->intf_nw_props.ip_add.ip_addr, nbr_intf->intf_nw_props.mask, nbr_masked );
  if(strncmp(intf_masked, nbr_masked, IP_LENGTH) != 0) return FALSE;
  
  return TRUE;
}





