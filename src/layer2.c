#include "../include/layer2.h"
#include "../include/hash.h"
#include "../include/tcpconst.h"
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include "../include/layer3.h"

extern void promote_pkt_to_l3(node_t *node, interface_t *recv_intf, char *payload, int protocol_number, unsigned int payload_size);
extern int send_pkt_flood(node_t *node, interface_t *exempted_intf, char *pkt, unsigned int pkt_size);

extern int send_pkt(char *pkt, unsigned int pkt_size, interface_t *interface);

extern void put_uchar_mac_into_char(unsigned char* mac, char *charred_mac);


static pthread_mutex_t timeout_checker_lock = PTHREAD_MUTEX_INITIALIZER;


typedef enum t {
  MAC_TABLE,
  ARP_TABLE
} mac_or_arp;

unsigned int get_access_intf_vlan_id(interface_t *intf){
  if(intf->intf_nw_props.l2_mode == ACCESS || intf->intf_nw_props.vlan_id[0] != 0)
    return intf->intf_nw_props.vlan_id[0]; 
  return -1; //fail
};

bool_t
is_trunk_interface_vlan_enabled(interface_t *intf, unsigned int vlan_id){
  if(intf->intf_nw_props.l2_mode == TRUNK) {
    // and has matching vlan id
    unsigned int* vlan_id_ptr = intf->intf_nw_props.vlan_id;

    while((*vlan_id_ptr) != 0) {
      if((*vlan_id_ptr) == vlan_id) return TRUE;
      vlan_id_ptr++;
    }
  }
  return FALSE;
};

static eth_hdr_t* alloc_eth_hdr_with_payload(char *pkt, unsigned int pkt_size) {
  eth_hdr_t *eth_hdr = (eth_hdr_t *)(pkt - ETH_HDR_SIZE_BEFORE_PAYLOAD);
  memset(eth_hdr, 0, ETH_HDR_SIZE_BEFORE_PAYLOAD);

  ETH_CRC(eth_hdr, pkt_size) = 0;
  return eth_hdr;
}

void dump_eth_hdr_pkt(eth_hdr_t *eth_hdr) {
  switch(eth_hdr->type) {
    //vlan configured
    case 0x8100: {
      vlan_eth_frame_t *vlan_eth_hdr = (vlan_eth_frame_t *)eth_hdr;
      printf("--- vlan hdr ---\n");
      printf("tpid : %x\n", vlan_eth_hdr->vlan_hdr.tpid);
      printf("pri : %d\n", vlan_eth_hdr->vlan_hdr.pri);
      printf("cfi : %d\n", vlan_eth_hdr->vlan_hdr.cfi);
      printf("vlan id : %d\n", vlan_eth_hdr->vlan_hdr.vlan_id);
      //printf("type")
      //printf("payload ")
      //printf("crc")
    }
    break;
    //vlan not configured
    default:
      break;

  }
}
char* untag_eth_vlan(vlan_eth_frame_t *eth_hdr, unsigned int *packet_size){
  char *hdr = (char *)eth_hdr;
  memset(hdr+2*sizeof(mac_add_t), 0, sizeof(vlan_802_1q_hdr_t));
  memmove(hdr+sizeof(vlan_802_1q_hdr_t), hdr, 2*sizeof(mac_add_t));
  hdr += 4;
  *packet_size -= sizeof(vlan_802_1q_hdr_t);
  return hdr;
}

char* tag_eth_vlan(eth_hdr_t *eth_hdr, unsigned int vlan_id, unsigned int *packet_size){
  // move hdr before type 4bytes(vlan_hdr_size)
  int mov_size = 2 * sizeof(mac_add_t); // 12 bytes
  char *hdr = (char *)eth_hdr;
  memmove(hdr-4, hdr, 12);
  hdr -= 4;
  vlan_802_1q_hdr_t *vlan_hdr = (vlan_802_1q_hdr_t *)(hdr+12);
  vlan_hdr->tpid = 0x8100;
  //pri, cfi are not used for now
  vlan_hdr->pri = 0;
  vlan_hdr->cfi = 0;
  vlan_hdr->vlan_id = vlan_id;
  *packet_size += 4;

  return hdr;
};
 

void init_arp_table(node_t *node){
  node->node_nw_props.ctr_arp_table = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
  make_hash_table(node->node_nw_props.ctr_arp_table, 2, ARP_T);
  init_hash_table(node->node_nw_props.ctr_arp_table, ARP_T);
};

void init_mac_table(node_t *node){
  node->node_nw_props.ctr_mac_table = (ctrl_table_t *)calloc(1, sizeof(ctrl_table_t));
  make_hash_table(node->node_nw_props.ctr_mac_table, 2, MAC_T);
  init_hash_table(node->node_nw_props.ctr_mac_table, MAC_T);
};

bool_t delete_arp_entry(node_t *node, char *ip_addr){
  if(deletion(node->node_nw_props.ctr_arp_table, ip_addr) == TRUE) return TRUE;
  return FALSE;
};
bool_t add_entry_to_arp_table(node_t *node, arp_entries_t* arp_entry){
  if(insert(node->node_nw_props.ctr_arp_table, arp_entry) == NULL) {
    printf("creating arp entry failed \n");
    return FALSE;
  }
  return TRUE;
};

arp_entries_t *arp_table_lookup(node_t *node, char *ip_addr){
  return (arp_entries_t *)search(node->node_nw_props.ctr_arp_table, ip_addr);
};

static void process_arp_pending_list_callback(arp_entries_t *arp_entry, interface_t *oif) {
  while(arp_entry->pending_pkts_count != 0) {
    int protocol_number = arp_entry->arp_pd_list->head->protocol_number;
    switch(protocol_number) {
      case ETH_IP: {
        eth_hdr_t *eth_pkt = (eth_hdr_t *)arp_entry->arp_pd_list->head->pkt;
        memcpy(eth_pkt->dest_mac.mac_addr, arp_entry->mac_addr.mac_addr, MAC_LENGTH);
        send_pkt((char*)eth_pkt, arp_entry->arp_pd_list->head->pkt_size, oif);
        arp_pending_entry_t *next_head = arp_entry->arp_pd_list->head->next_pd_pkt;
        free(arp_entry->arp_pd_list->head);
        arp_entry->pending_pkts_count --;
        arp_entry->arp_pd_list->head = next_head;
        if(arp_entry->pending_pkts_count == 0) arp_entry->arp_pd_list->tail = arp_entry->arp_pd_list->head;// set tail to null
      }
      default: break;
    }
  }
  arp_entry->is_sane = TRUE;
  return;
}

//from arp reply , update
bool_t update_arp_entry(node_t *node, arp_hdr_t *arp_hdr, interface_t *iif){
  arp_entries_t *found_arp_entry;
  arp_entries_t *to_be_updated = (arp_entries_t *)calloc(1, sizeof(arp_entries_t));
  inet_ntop(AF_INET, &arp_hdr->src_ip, to_be_updated->ip_addr.ip_addr, 16);
  // save src mac
  memcpy(to_be_updated->mac_addr.mac_addr, arp_hdr->src_mac.mac_addr, 6);
  strncpy(to_be_updated->oif_name, iif->name, IF_NAME_SIZE);
  to_be_updated->is_sane = TRUE;

  if(arp_hdr->op_code == ARP_REPLY){
    // check if insane
    if((found_arp_entry = search(node->node_nw_props.ctr_arp_table, to_be_updated->ip_addr.ip_addr)) != NULL && found_arp_entry->is_sane == FALSE) {
      memcpy(found_arp_entry->mac_addr.mac_addr, to_be_updated->mac_addr.mac_addr, MAC_LENGTH);
      memcpy(found_arp_entry->oif_name, to_be_updated->oif_name, IF_NAME_SIZE);
      process_arp_pending_list_callback(found_arp_entry, iif);
      return TRUE;
    }
    
    if(add_entry_to_arp_table(node, to_be_updated) == FALSE) {
      free(to_be_updated);
      
      return FALSE;
    }
    return TRUE;
  } else if(arp_hdr->op_code == ARP_REQUEST) {
    // if exist, update entry and return
    if((found_arp_entry = search(node->node_nw_props.ctr_arp_table,  to_be_updated->ip_addr.ip_addr)) != NULL) {
      memcpy(found_arp_entry->mac_addr.mac_addr, to_be_updated->mac_addr.mac_addr, 6);
      strncpy(found_arp_entry->oif_name, to_be_updated->oif_name, IF_NAME_SIZE);
      free(to_be_updated); 
      return TRUE;
    }
    // 여기
    // if not, create and return
    if(add_entry_to_arp_table(node, to_be_updated) == FALSE) {
      free(to_be_updated);
      return FALSE;
    }
    return TRUE;
  }
  return FALSE;
};
void dump_arp_entry(node_t *node){
  graph_elements_t *table = node->node_nw_props.ctr_arp_table->table_ptr;

  printf("---Node %s arp table ---\n", node->name);
  int size = node->node_nw_props.ctr_arp_table->curr_size;
  int i = 0;
  while(i < size) {
    arp_entries_t *arp_table_entry = ((arp_entries_t *)table->entry);
    if(table->is_entry){
      i++;
      printf("ip address : %s\n", arp_table_entry->ip_addr.ip_addr);
      printf("mac address : ");
      for(int i = 0 ; i < MAC_LENGTH; i++) {
        if(i != 0) printf(":");
        printf("%x", arp_table_entry->mac_addr.mac_addr[i]);
      } 
      printf("\noutgoing interface : %s\n\n", arp_table_entry->oif_name);
    }
    table++;
  }
};

void free_arp_table(node_t *node){
  int size = node->node_nw_props.ctr_arp_table->curr_size;
  graph_elements_t* cur = node->node_nw_props.ctr_arp_table->table_ptr;
  
  int i = 0;
  while(i < size){
    arp_entries_t *arp_table_entry = ((arp_entries_t *)cur->entry);
    if(cur->is_entry) {
      int k = 0;
      //printf("freeing : %s\n", arp_table_entry->oif_name);
      i++;
      free(cur->entry);
    }
    cur++;
  };
  // free(node->node_nw_props.ctr_arp_table->arp_table);
  free(node->node_nw_props.ctr_arp_table->table_ptr);
  free(node->node_nw_props.ctr_arp_table); 
};

eth_hdr_t *make_arp_broadcast_msg(interface_t *oif, char *ip_addr){
  unsigned int available_size = sizeof(arp_hdr_t)+VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
  char *payload = (char *)calloc(1, available_size);
  arp_hdr_t *arp_payload = (arp_hdr_t *)calloc(1, sizeof(arp_hdr_t));
  arp_payload->hw_type = 1; // Ethernet
  arp_payload->protocol_type = ETH_IP; // 0x0800 : IPV4
  arp_payload->hw_addr_len = 6; // in octets : 48 bits
  arp_payload->protocol_addr_len = 4; //ipv4 in octets
  if(oif->intf_nw_props.l2_mode == TRUNK) {
    char ip1[IP_LENGTH];
    char ip2[IP_LENGTH];
    apply_mask(ip_addr, oif->intf_nw_props.mask, ip2);
    for(int i=0; ; i++){
      apply_mask(oif->intf_nw_props.vlan_id_binded_ip[i].ip_addr, oif->intf_nw_props.mask, ip1);
      if(strncmp(ip1, ip2, IP_LENGTH) == 0) {
        arp_payload->src_ip = ip_addr_p_to_n(oif->intf_nw_props.vlan_id_binded_ip[i].ip_addr);
        break;
      }
    }
  } 
  else arp_payload->src_ip = ip_addr_p_to_n(oif->intf_nw_props.ip_add.ip_addr);
  arp_payload->op_code = ARP_REQUEST;
  memcpy(arp_payload->src_mac.mac_addr, oif->intf_nw_props.mac_add.mac_addr, sizeof(mac_add_t));
  memset(arp_payload->dest_mac.mac_addr , 0, MAC_LENGTH);
  arp_payload->dest_ip = ip_addr_p_to_n(ip_addr);

  payload += sizeof(vlan_802_1q_hdr_t);
  // wrap ethernet header
  eth_hdr_t *eth_hdr = (eth_hdr_t *)payload;
  layer2_fill_with_broadcast_mac(eth_hdr->dest_mac.mac_addr);
  memcpy(eth_hdr->src_mac.mac_addr, oif->intf_nw_props.mac_add.mac_addr, sizeof(mac_add_t));
  eth_hdr->type = 806;
  memcpy(eth_hdr->payload, arp_payload, sizeof(arp_hdr_t));
  ETH_CRC(eth_hdr, sizeof(arp_hdr_t)) = 0;    
  free(arp_payload);
  return eth_hdr;
};

// for only one interface
void send_arp_broadcast_msg_excl(node_t *node, char *ip_addr, char* oif, unsigned int vlan_id){
  // get intf
  interface_t *intf = get_node_if_by_name(node, oif);
  eth_hdr_t *eth_hdr;
  eth_hdr = make_arp_broadcast_msg(intf, ip_addr);
  unsigned int pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t);
  // if trunk : send out with vlan configured
  if(intf->intf_nw_props.l2_mode == TRUNK && vlan_id > 0) {
    char *vlan_frm = tag_eth_vlan(eth_hdr, vlan_id, &pkt_size);
   // printf("up sending broadcast arp excl %s from : %s\n", node->name, oif);
    if(send_pkt(vlan_frm, pkt_size, intf) != 1) {
        free(eth_hdr);
    }  
    return;
  }
  // normal ethernet hdr
  else {
   // printf("sending broadcast arp excl %s from : %s\n", node->name, oif);
    if(send_pkt((char *)eth_hdr, pkt_size, intf) != 1) {
        free(eth_hdr);
    }  
    return;
  }
}

void send_arp_broadcast_msg_flood(node_t *node, char *ip_addr, char *exclusive_if){
  int until = get_node_intf_available_slot(node);
  if(exclusive_if != NULL) {
    for(int i = 0; i < until; i++) {
      interface_t *oif = node->if_list[i];
      if(strncmp(oif->name, exclusive_if, IF_NAME_SIZE) != 0) continue;
      eth_hdr_t *eth_hdr;
      eth_hdr = make_arp_broadcast_msg(oif, ip_addr);
    //  printf("sending broadcast arp %s from : %s\n", node->name, oif->name);
      if(send_pkt((char *)eth_hdr, ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t), oif) != 1) {
        free(eth_hdr);
      }     
    }
  }
  else {
  // make arp payload
  for(int i = 0 ; i < until; i++){
    interface_t *oif = node->if_list[i];
    eth_hdr_t *eth_hdr;
    eth_hdr = make_arp_broadcast_msg(oif, ip_addr);
  //  printf("sending broadcast arp to : %s\n", oif->name);
    if(send_pkt((char *)eth_hdr, ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t), oif) != 1) {
      free(eth_hdr);
    }
    // free(eth_hdr);
  }
  }
};

void send_arp_reply(interface_t *oif, eth_hdr_t *recvd_eth){

 // iif 로 arp_reply hdr message
 // printf("sending arp reply , on ip : %s, intf : %s\n", oif->intf_nw_props.ip_add.ip_addr, oif->name);
  arp_hdr_t *reply_arp;
  // deciding payload position
  if(recvd_eth->type == 0x8100) reply_arp = (arp_hdr_t *)(((vlan_eth_frame_t *)recvd_eth)->payload);
  else reply_arp = (arp_hdr_t *)(recvd_eth->payload);
  reply_arp->op_code = ARP_REPLY;
  unsigned char dest_mac[MAC_LENGTH];
  memcpy(dest_mac,reply_arp->src_mac.mac_addr,MAC_LENGTH);

  memcpy(reply_arp->src_mac.mac_addr, oif->intf_nw_props.mac_add.mac_addr, MAC_LENGTH);
  uint32_t src_ip = reply_arp->dest_ip;
  uint32_t dest_ip = reply_arp->src_ip;
  memcpy(&reply_arp->src_ip, &src_ip, sizeof(uint32_t)); 
  memcpy(reply_arp->dest_mac.mac_addr, dest_mac, MAC_LENGTH);
  memcpy(&reply_arp->dest_ip, &dest_ip, sizeof(uint32_t));

  //eth destmac : eth_hdr 에서 받았던 mac address
  if(recvd_eth->type == 0x8100){
    memcpy(((vlan_eth_frame_t *)recvd_eth)->dest_mac.mac_addr, ((vlan_eth_frame_t *)recvd_eth)->src_mac.mac_addr, MAC_LENGTH);
    memcpy(((vlan_eth_frame_t *)recvd_eth)->src_mac.mac_addr, oif->intf_nw_props.mac_add.mac_addr, MAC_LENGTH);
    VLAN_ETH_CRC((vlan_eth_frame_t *)recvd_eth, sizeof(arp_hdr_t)) = 0;
    send_pkt((char *)recvd_eth, VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t), oif);
  } else {
    memcpy(recvd_eth->dest_mac.mac_addr, recvd_eth->src_mac.mac_addr, MAC_LENGTH);
    memcpy(recvd_eth->src_mac.mac_addr, oif->intf_nw_props.mac_add.mac_addr, MAC_LENGTH);
    ETH_CRC(recvd_eth, sizeof(arp_hdr_t)) = 0;

    send_pkt((char*)recvd_eth, ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t), oif);
  }

};

void process_arp_broadcast(interface_t *iif, eth_hdr_t* recvd_eth, unsigned int pkt_size){
  
  unsigned int payload_size;
  arp_hdr_t *arp_hdr;
  unsigned int vlan_id = 0;
  //printf("arp broadcast message received at %s of node %s\n", iif->name, iif->node->name);
  // if vlan
  if(recvd_eth->type == 0x8100) { 
    payload_size = pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
    arp_hdr = (arp_hdr_t *)((vlan_eth_frame_t *)recvd_eth)->payload;
    vlan_id = ((vlan_eth_frame_t *)recvd_eth)->vlan_hdr.vlan_id;
  } else {
    payload_size = pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD;
    arp_hdr = (arp_hdr_t *)recvd_eth->payload;
  }
  //update arp if not exist
  update_arp_entry(iif->node, arp_hdr, iif);
  
  // check if the destination ip address is same with current
  char ip_addr[16];
  //dest - ip is already in network byte order
  ip_addr_n_to_p(arp_hdr->dest_ip, ip_addr);
  ip_addr[15] = '\0';
  //check vlan_id and its ip address (for svi)
  char is_matching_svi = 0;
  if(vlan_id > 0) {
    for(int i=0; ;i++) {
      if(iif->intf_nw_props.vlan_id[i] == vlan_id) {
        is_matching_svi = (strncmp(iif->intf_nw_props.vlan_id_binded_ip[i].ip_addr, ip_addr, IP_LENGTH) == 0) ? 1 : 0;
        break;
      }
    }
  }
  if(!strncmp(ip_addr, iif->intf_nw_props.ip_add.ip_addr, IP_LENGTH) || is_matching_svi) {
    send_arp_reply(iif, recvd_eth);
  }


  return;
}

void process_arp_reply(interface_t *iif, arp_hdr_t *arp_to_add){

  printf("arp reply message received, dest mac : %x:%x:%x:%x:%x:%x\n", arp_to_add->src_mac.mac_addr[0],arp_to_add->src_mac.mac_addr[1],arp_to_add->src_mac.mac_addr[2],arp_to_add->src_mac.mac_addr[3],arp_to_add->src_mac.mac_addr[4],arp_to_add->src_mac.mac_addr[5]);
  update_arp_entry(iif->node, arp_to_add, iif);

};
//should be updated to real implementation of checking checksum
/*bool_t check_checksum(eth_hdr_t *pkt, unsigned int data_size){
  vlan_802_1q_hdr_t *vlan_hdr = get_vlan_hdr_from_pkt(pkt);
  pkt_dump(pkt, data_size);
  if(vlan_hdr != NULL) {
    if(VLAN_ETH_CRC((vlan_eth_frame_t *)pkt, data_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD) != 0) {
      printf("CRC value not valid vlan %d\n", VLAN_ETH_CRC((vlan_eth_frame_t *)pkt, data_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD));
      printf("data size : %d, excl payload size : %ld\n ", data_size, VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD);
      return FALSE;
    }
  }
  else {
    if(ETH_CRC((eth_hdr_t *)pkt, data_size - ETH_HDR_SIZE_EXCL_PAYLOAD) != 0) {
        printf("CRC value not valid %d\n", ETH_CRC((eth_hdr_t *)pkt, data_size - ETH_HDR_SIZE_EXCL_PAYLOAD));
        printf("data size : %d, excl payload size : %ld\n ", data_size, ETH_HDR_SIZE_EXCL_PAYLOAD);
        return FALSE;
    }
  }
  return TRUE;
};
*/
static bool_t l2_qualified_frame (interface_t* intf, char *data, unsigned int data_size) {
  //1. if ip is not configured, return false : arp resolution need receiving node's ip
  if((intf->intf_nw_props.is_ip_config == FALSE) && (intf->intf_nw_props.l2_mode == UNDEFINED)) {
    return FALSE;
  }
  //2. checksum : if it not matches, reject : for here, checksum value is 0 for now


  //3. if dest mac is matching or it is l2 broadcast request, return TRUE
  if(!memcmp(((eth_hdr_t*)data)->dest_mac.mac_addr, intf->intf_nw_props.mac_add.mac_addr, 6) || IS_MAC_BROADCAST_ADDR(((eth_hdr_t*)data)->dest_mac.mac_addr)) {
    return TRUE;
  }
  if(intf->intf_nw_props.l2_mode == ACCESS || intf->intf_nw_props.l2_mode == TRUNK) return TRUE;
  if(intf->intf_nw_props.is_ip_config == TRUE) return TRUE;
  printf("undefined behavior : return FALSE \n");
  return FALSE;
}



// and add entry in mac table 
bool_t l2_switch_recv_frame(node_t *node, interface_t *iif, char **data, unsigned int *data_size, vlan_802_1q_hdr_t* v_hdr){
 // printf("received on switch %s\n", node->name);
  l2_mode_t mode = iif->intf_nw_props.l2_mode;
  // start_checktimeout_thread(node->node_nw_props.ctr_mac_table, MAC_TABLE);
  //matching tag
  unsigned int intf_vid;
   
  if((intf_vid= get_access_intf_vlan_id(iif)) <= 0) {
    printf("ERROR : vlan id not configured on interface %s\n", iif->name);
    assert(0);
  }
  if(mode == ACCESS) {
    if(v_hdr) {
      // assert(GET_802_1Q_VLAN_ID(vlan_hdr) == get_access_intf_vlan_id(iif));
      if(v_hdr->vlan_id != intf_vid) {
        printf("access vlan id not matching.. terminating \n");
        return FALSE;
      }
    }
    else {
      
      *data = tag_eth_vlan((eth_hdr_t *)*data, intf_vid , data_size);
      //pkt's address has changed, so we have to change data according to it
      //printf("l2 switch %s tagged \n", node->name);
      // *data = (char *)pkt; 
    }
  }
  else if(mode == TRUNK){
    //printf("l2 switch %s trunk mode , vlan id %d\n", node->name, v_hdr->vlan_id);
    // assert(vlan_hdr && is_trunk_interface_vlan_enabled(iif, GET_802_1Q_VLAN_ID(vlan_hdr)) == TRUE);
    if(get_vlan_hdr_from_pkt((eth_hdr_t *)*data) == NULL || (is_trunk_interface_vlan_enabled(iif,v_hdr->vlan_id) == FALSE)) {
      return FALSE;
    }
  }

  mac_entry_t *found_entry;
  char mac[13];
  // receive : put src mac address in mac table
  put_uchar_mac_into_char(((eth_hdr_t *)(*data))->src_mac.mac_addr, mac);
  
  found_entry = mac_table_lookup(node, mac);
  //if not, add the src mac address
  if(found_entry == NULL) {
    add_mac_entry(node, &((eth_hdr_t *)(*data))->src_mac, iif->name, iif->intf_nw_props.vlan_id[0]);
	//printf("mac entry added %s\n", node->name);
  }
  
  time_t curr_time = time(NULL);

  if(found_entry != NULL && ((curr_time - found_entry->issued_time) > 20)) {
    found_entry = NULL;
  }  
  return TRUE;
}
void l2_switch_send_pkt_flood (node_t *node, interface_t* exempted_if, char *data, unsigned int *data_size, unsigned int vlan_id) {

  int until = get_node_intf_available_slot(node);
  for(int i=0; i< until; i++){
    // check vlan id of each interface
    // send pkt except iif /case 1 : ACCESS, 2:TRUNK

    unsigned int *v_id = node->if_list[i]->intf_nw_props.vlan_id;
    if((node->if_list[i]->intf_nw_props.l2_mode == ACCESS) && v_id[0] == vlan_id && ((strncmp(node->if_list[i]->name, exempted_if->name, IF_NAME_SIZE)) != 0)) {
      //untag the frame if access mode
      //printf("node %s send pkt to intf %s\n", node->name, node->if_list[i]->name);
      data = untag_eth_vlan((vlan_eth_frame_t*)data, data_size);
      send_pkt(data, *data_size, node->if_list[i]);
      //for next pkt, recover it
      data = tag_eth_vlan((eth_hdr_t*)data, vlan_id, data_size);
    }
    else if((node->if_list[i]->intf_nw_props.l2_mode == TRUNK) && ((strncmp(node->if_list[i]->name, exempted_if->name, IF_NAME_SIZE)) != 0)) {
      int k = 0;
      while(*(v_id+k) != 0){
        if(v_id[k] == vlan_id) {
      //printf("TRUNK node %s send pkt from intf %s, exempted %s, vlan id %d\n", node->name, node->if_list[i]->name, exempted_if->name, ((vlan_eth_frame_t*)data)->vlan_hdr.vlan_id);
          pkt_dump((eth_hdr_t*)data, *data_size);
          send_pkt(data, *data_size, node->if_list[i]);
          break;
        }
        k++;
      }
    }
  }
};

bool_t l2_switch_forward_frame(node_t *node, interface_t *iif, char *data, unsigned int* data_size) {
 // printf("l2 switch %s forwarding \n", node->name);

  mac_entry_t *found_entry;
  l2_mode_t mode = iif->intf_nw_props.l2_mode;
  vlan_802_1q_hdr_t *vlan_hdr;
  vlan_hdr = get_vlan_hdr_from_pkt((eth_hdr_t *)data);
  char mac[13];

  put_uchar_mac_into_char(((eth_hdr_t*)data)->dest_mac.mac_addr, mac);

  if(IS_MAC_BROADCAST_ADDR(((eth_hdr_t*)data)->dest_mac.mac_addr) || ((found_entry = mac_table_lookup(node, mac)) == NULL)) {

    //vlan not configured
    if((vlan_hdr) == NULL) { 
      printf("\npkt vlan not configured in l2 switch, termingating \n");
      assert(0);
    }
    //vlan configured
    l2_switch_send_pkt_flood(node, iif, data, data_size, vlan_hdr->vlan_id);
    return TRUE;
  }
  // if it is not broadcast if destination address is there, simply forward it to that outgoin interface
  
  interface_t* oif = get_node_if_by_name(node, found_entry->oif_name);

  //sending pkt 
  if(vlan_hdr && oif->intf_nw_props.vlan_id[0] == 0) {
    // oif is not configured with vlan : return FALSE, could be scaled out to Native vlan
    return FALSE;
  }

  switch(oif->intf_nw_props.l2_mode) {
    case UNDEFINED:{
      //fail
      return FALSE;
    }
    case ACCESS:{
      //vlan configured
      if(vlan_hdr) {
        // if vlan is same
        if(oif->intf_nw_props.vlan_id[0] == vlan_hdr->vlan_id) {
          //untag because access neighbor unaware of vlan
    
          data = untag_eth_vlan((vlan_eth_frame_t *)data, data_size);

          send_pkt(data, *data_size, oif);
          return TRUE;
        }
        printf("no matching vlan \n");
        return FALSE;
      }
      //vlan not configured : drop (fail)
      return FALSE;
    }
    case TRUNK:{
      //should be vlan_hdr && corresponding vlan_id
      assert(vlan_hdr);
      int k = 0;
      unsigned int *v_id = oif->intf_nw_props.vlan_id;
      while(v_id[k] != 0) {
        if(v_id[k] == vlan_hdr->vlan_id) {
          send_pkt(data, *data_size, oif);
          return TRUE;
        }
        k++;
      }
      return FALSE;
    }
  }
  printf("something went wrong : in l2 switch forward frame\n");
  return FALSE;
}

void promote_pkt_to_l2(node_t *node, interface_t *iif, eth_hdr_t *pkt, unsigned int data_size){
  
  vlan_802_1q_hdr_t *vlan_hdr = get_vlan_hdr_from_pkt(pkt);
  unsigned short type;
  arp_hdr_t *payload;
  char *ip_hdr;
  if(vlan_hdr) {
    type = ((vlan_eth_frame_t *)pkt)->type;
    payload = (arp_hdr_t *)((vlan_eth_frame_t *)pkt)->payload;
  }
  else {
    type = pkt->type;
    payload = (arp_hdr_t*)(pkt)->payload;
  }
  switch(type){
    case 806: //arp request/ARP_REPLY
      switch(payload->op_code){
        case ARP_REQUEST:
          process_arp_broadcast(iif, pkt, data_size);
          return;
        case ARP_REPLY:
          process_arp_reply(iif, payload);
          return;
      }
        // }
    case ETH_IP: {
      char *ip_hdr = get_eth_hdr_payload(pkt);
      data_size -= (vlan_hdr != NULL) ? VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD : ETH_HDR_SIZE_EXCL_PAYLOAD;
      promote_pkt_to_l3(node, iif, ip_hdr, type, data_size);
      return;
    }
  default:
  break;
  }

};

void l2_recv_frame(node_t *node, char *intf_name, char *data, unsigned int data_size){
   //pkt_dump((eth_hdr_t *) data, data_size);
   interface_t *iif = get_node_if_by_name(node, intf_name);
   if(l2_qualified_frame(iif, data, data_size) == FALSE) {
     printf("Layer 2 frame rejected\n");
     return;
   }
   eth_hdr_t *pkt = (eth_hdr_t *)data;
      //check if vlan configured
   vlan_802_1q_hdr_t* vlan_hdr;
   //if not, vlan_hdr == NULL
   vlan_hdr = get_vlan_hdr_from_pkt(pkt);
   //if this interface is configured with l2 mode, 
   l2_mode_t mode = iif->intf_nw_props.l2_mode;

   // for l2 mode configured switch 
   if((mode == ACCESS || mode == TRUNK) && iif->intf_nw_props.is_svi_config == FALSE) {
     if(l2_switch_recv_frame(node, iif, &data, &data_size, vlan_hdr) == FALSE) {
      printf("l2 switch recv failed \n");
      return;
     };
     // data is already tagged by l2_switch_recv_frame
     l2_switch_forward_frame(node, iif, data, &data_size);
     return;
   }
   //if interface not configured with l2mode, the message should be untagged message -> SVI
  //  assert(vlan_hdr == NULL);

   // final check : should be ip configured / svi interface
   assert(IS_INTF_L3_MODE(iif) == TRUE || iif->intf_nw_props.is_svi_config == TRUE);
   promote_pkt_to_l2(node, iif, pkt, data_size);
};


void add_mac_entry(node_t* node, mac_add_t *mac_addr, char *intf_name, unsigned int vlan_id){
  time_t curr_time_sec = time(NULL);
  mac_entry_t *new_mac_entry = (mac_entry_t *)calloc(1, sizeof(mac_entry_t));
  new_mac_entry->issued_time = curr_time_sec;
  memcpy(new_mac_entry->mac_addr.mac_addr, mac_addr->mac_addr, 6);
  strncpy(new_mac_entry->oif_name, intf_name, IF_NAME_SIZE);
  new_mac_entry->oif_name[IF_NAME_SIZE-1] = '\0';
  new_mac_entry->vlan_id = vlan_id;
  
  insert(node->node_nw_props.ctr_mac_table, new_mac_entry);

};

bool_t delete_mac_entry(node_t* node, mac_add_t* mac_addr){
  char mac[13];
  put_uchar_mac_into_char(mac_addr->mac_addr, mac);

  return deletion(node->node_nw_props.ctr_mac_table, mac);
};


// this mac_address should be filtered through put_uchar_mac_into_char function
mac_entry_t *mac_table_lookup(node_t* node, char* mac_addr){
  mac_entry_t *found;
  // time_t curr_time = time(NULL);

  found = search(node->node_nw_props.ctr_mac_table, mac_addr);
  // if((curr_time - found->issued_time) > 20) {
  //   return NULL;
  // }
  return found;
};
void dump_mac_entry(node_t *node){
  printf("-----Node %s mac table-----\n", node->name);
  int curr_size = node->node_nw_props.ctr_mac_table->curr_size;
  int i = 0;
  // mac_table_t *mac_table = node->node_nw_props.ctr_mac_table->mac_table;
  graph_elements_t *mac_table = node->node_nw_props.ctr_mac_table->table_ptr;
  
  while(i < curr_size){
    mac_entry_t **mac_entry = (mac_entry_t **)&mac_table->entry;
    if(mac_table->is_entry){
      i++;
      printf("mac address : %x:%x:%x:%x:%x:%x\n", (*mac_entry)->mac_addr.mac_addr[0], (*mac_entry)->mac_addr.mac_addr[1], (*mac_entry)->mac_addr.mac_addr[2], (*mac_entry)->mac_addr.mac_addr[3], (*mac_entry)->mac_addr.mac_addr[4], (*mac_entry)->mac_addr.mac_addr[5]);
      printf("oif : %s\n", (*mac_entry)->oif_name);

      char* time_str = ctime(&(*mac_entry)->issued_time);
      time_str[strlen(time_str)-1] = '\0';
      printf("time created : %s\n", time_str);
    }
    mac_table++;
  }
};

void pkt_dump(eth_hdr_t* eth_pkt, unsigned int pkt_size) {
  if(get_vlan_hdr_from_pkt(eth_pkt) != NULL) {
    printf("dest mac: ");
    for(int i = 0 ; i < MAC_LENGTH; i++) {
      if(i != 0) printf(":");
      printf("%x", ((vlan_eth_frame_t *)eth_pkt)->dest_mac.mac_addr[i]);
    }
    printf("\nsrc mac: ");
    for(int i = 0 ; i < MAC_LENGTH; i++) {
      if(i != 0) printf(":");
      printf("%x", ((vlan_eth_frame_t *)eth_pkt)->src_mac.mac_addr[i]);
    }
    printf("\ntpid : %x", ((vlan_eth_frame_t *)eth_pkt)->vlan_hdr.tpid);
    printf("\npri : %d", ((vlan_eth_frame_t *)eth_pkt)->vlan_hdr.pri);
    printf("\ncfi : %d", ((vlan_eth_frame_t *)eth_pkt)->vlan_hdr.cfi);
    printf("\nvlan_id : %d", ((vlan_eth_frame_t *)eth_pkt)->vlan_hdr.vlan_id);
    printf("\ntype : %d", ((vlan_eth_frame_t *)eth_pkt)->type);
    if(((vlan_eth_frame_t *)eth_pkt)->type == 806) {
      char dest_ip[16];
      char src_ip[16];
      ip_addr_n_to_p(((arp_hdr_t *)(((vlan_eth_frame_t *)eth_pkt)->payload))->dest_ip, dest_ip);
      printf("\narp :: dest ip: %s", dest_ip);
      ip_addr_n_to_p(((arp_hdr_t *)(((vlan_eth_frame_t *)eth_pkt)->payload))->src_ip, src_ip);
      printf("\narp :: src ip: %s", src_ip);
      printf("\narp :: src mac: ");
      for(int i = 0 ; i < MAC_LENGTH; i++) {
        if(i != 0) printf(":");
        printf("%x", ((arp_hdr_t *)(((vlan_eth_frame_t *)eth_pkt)->payload))->src_mac.mac_addr[i]);
      }
      printf("\narp :: dest mac: ");
      for(int i = 0 ; i < MAC_LENGTH; i++) {
        if(i != 0) printf(":");
        printf("%x", ((arp_hdr_t *)(((vlan_eth_frame_t *)eth_pkt)->payload))->dest_mac.mac_addr[i]);
      }
    }
    printf("\ncrc : %d ", VLAN_ETH_CRC(((vlan_eth_frame_t *)eth_pkt), pkt_size - VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD));
  } else {
    printf("dest mac: ");
    for(int i = 0 ; i < MAC_LENGTH; i++) {
      if(i != 0) printf(":");
      printf("%x", eth_pkt->dest_mac.mac_addr[i]);
    }
    printf("\nsrc mac: ");
    for(int i = 0 ; i < MAC_LENGTH; i++) {
      if(i != 0) printf(":");
      printf("%x", eth_pkt->src_mac.mac_addr[i]);
    }
    printf("\ntype : %d", eth_pkt->type);
    if(eth_pkt->type == 806) {
      char dest_ip[16];
      ip_addr_n_to_p(((arp_hdr_t *)(eth_pkt->payload))->dest_ip, dest_ip);
      printf("\narp :: dest ip: %s", dest_ip);
      printf("\narp :: dest mac: ");
      for(int i = 0 ; i < MAC_LENGTH; i++) {
        if(i != 0) printf(":");
        printf("%x", ((arp_hdr_t *)(eth_pkt->payload))->dest_mac.mac_addr[i]);
      }
    }
    printf("\ncrc : %d ", ETH_CRC(eth_pkt, pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD));
  }
};

/*
void set_stp(ctrl_table_t *topo){
  // find root switch
  unsigned int curr_size = topo->table_size;
  
  int cur = 0;
  int max_pri = 0;
  unsigned int switch_id_of_max = 0;
  while(cur < curr_size) {
    graph_elements_t *graph = topo->table_ptr+cur;
    if(graph[cur].is_entry) {
      cur++;
      if(((node_t*)graph[cur].entry)->node_nw_props.priority > max_pri) {
        max_pri = ((node_t*)graph[cur].entry)->node_nw_props.priority;
        // there are many mac address, how i configure switch ID
        // switch_id_of_max = ((node_t*)graph[cur].entry)->
      }
    }
  }
  // calculate shortest path to the root switch

  // set each port to root port

  // set facing port to designated port

  // find link with no root port/designated port configured

  // set one of that port to designated port (the one with lower switch ID)

  // set other port to BLOCKED port
};*/
/*
void send_bpdu(node_t *sw) {
  //make pkt

  // typedef struct bpdu_ {
  // uint16_t protocol_id;
  // uint8_t version;
  // uint8_t message_type;
  // uint8_t flags;

  // uint8_t root_id[8];
  // uint32_t cost_of_path;
  // uint8_t bridge_id[8];
  // uint16_t port_id;
  
  // uint16_t message_age;
  // uint16_t max_age;
  // uint16_t hello_time;
  // uint16_t forward_delay;
  bpdu_t *bpdu = (bpdu_t *)calloc(1, sizeof(bpdu_t));
  bpdu->protocol_id = 0;
  bpdu->message_type = 0;
  bpdu->version = 0;
  bpdu->flags = 0;
  bpdu->message_age = 0;
  bpdu->hello_time = 0;
  bpdu->forward_delay = 0;
  bpdu->max_age = 0;

  
  

  //multicast, eth
} 
*/
static void append_to_arp_pending_list(arp_entries_t *arp_entry, char *pkt, int protocol_number, unsigned int pkt_size){
  // make new arp_pd_entry

  arp_pending_entry_t *arp_pd_entry = (arp_pending_entry_t *)calloc(1, sizeof(arp_pending_entry_t));
  arp_pd_entry->protocol_number = protocol_number;
  arp_pd_entry->next_pd_pkt = NULL;
  arp_pd_entry->pkt = pkt;
  arp_pd_entry->pkt_size = pkt_size;
  //if new
  char *pkt_ = get_eth_hdr_payload((eth_hdr_t *)pkt);
  ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_;
  if(arp_entry->pending_pkts_count == 0) {
    //create new one
    arp_pd_list_head_tail_t *arp_ht = (arp_pd_list_head_tail_t *)calloc(1, sizeof(arp_pd_list_head_tail_t));
    arp_ht->head = arp_pd_entry;
    arp_ht->tail = arp_pd_entry;

    arp_entry->arp_pd_list = arp_ht;
    arp_entry->pending_pkts_count = 1;
    return;
  }
  // already exist : find tail and append
  arp_pending_entry_t *tail_entry = arp_entry->arp_pd_list->tail;
  arp_pd_entry->next_pd_pkt = tail_entry->next_pd_pkt;
  tail_entry->next_pd_pkt = arp_pd_entry;

  arp_entry->arp_pd_list->tail = arp_pd_entry;
  arp_entry->pending_pkts_count ++;
  return;
}

static arp_entries_t *init_insane_arp_entry(char *ip) {
  arp_entries_t *insane_arp_entry = (arp_entries_t *)calloc(1, sizeof(arp_entries_t));
  insane_arp_entry->pending_pkts_count = 0; 
  insane_arp_entry->is_sane = FALSE;
  memcpy(insane_arp_entry->ip_addr.ip_addr,ip, IP_LENGTH);

  return insane_arp_entry;
}

static void l2_forward_eth_ip_frm(node_t *node, unsigned int nexthop_ip, char *pkt, unsigned int pkt_size, interface_t *out_intf, unsigned int protocol_number, unsigned int vlan_id){
  char *oif = out_intf->name;
  arp_entries_t *arp_entry;
  char ip[IP_LENGTH];
  //interface_t *out_intf = get_node_if_by_name(node, oif);
  //pack frame with ethernet header without destination mac address
  memmove(pkt - 4, pkt, pkt_size);
  pkt -= 4;
  eth_hdr_t *eth_frm = alloc_eth_hdr_with_payload(pkt, pkt_size);
  memcpy(eth_frm->src_mac.mac_addr, IF_MAC(out_intf), MAC_LENGTH);
  eth_frm->type = protocol_number; // 0x0800 = IPv4
  // send pkt to next hop 
  pkt_size += ETH_HDR_SIZE_EXCL_PAYLOAD;

  // 1. forwarding
  if(nexthop_ip) {
    ip_addr_n_to_p(nexthop_ip, ip);

    assert(out_intf);
    // search arp table the nexthop_ip mac
    arp_entry = arp_table_lookup(node, ip);
    if(arp_entry == NULL) {
      //insane arp entry : arp resolution should be done
      arp_entries_t *insane_arp_entry = init_insane_arp_entry(ip);
      // queue : fcfs
      // if outgoin interface configured with vlan trunk mode
      if(out_intf->intf_nw_props.l2_mode == TRUNK && vlan_id > 0) {
        // tag it with vlan id
        char *vlan_frame = tag_eth_vlan(eth_frm, vlan_id, &pkt_size);
        append_to_arp_pending_list(insane_arp_entry, vlan_frame, protocol_number, pkt_size);
      }
      else {
        append_to_arp_pending_list(insane_arp_entry, (char *)eth_frm, protocol_number, pkt_size);
      }
      
      add_entry_to_arp_table(node, insane_arp_entry);
      if(vlan_id > 0) send_arp_broadcast_msg_excl(node, ip, oif, vlan_id);
      else {
		  send_arp_broadcast_msg_flood(node, ip, oif);
	  }// else send_arp_broadcast_msg_excl(node, ip, oif, vlan_id);
      return;
    }
    if(arp_entry->is_sane == FALSE) {
      // append and return
      if(out_intf->intf_nw_props.l2_mode == TRUNK && vlan_id > 0) {
        // tag it with vlan id
        vlan_eth_frame_t *vlan_frame = (vlan_eth_frame_t *)tag_eth_vlan(eth_frm, vlan_id, &pkt_size);
        append_to_arp_pending_list(arp_entry, (char *)vlan_frame, protocol_number, pkt_size);
      }
      else append_to_arp_pending_list(arp_entry, (char *)eth_frm, protocol_number, pkt_size);
      return;
    } 
    //else : arp_entry is sane, so allowed to send out pkt
    //make pkt to make room for checksum
    memcpy(eth_frm->dest_mac.mac_addr, arp_entry->mac_addr.mac_addr, MAC_LENGTH);
    // send pkt to next hop 

    send_pkt((char *)eth_frm, pkt_size, out_intf);
    return;
  }
  // if oif specified
  // 2. local subnet
  else if(!nexthop_ip && oif) {  
    //for svi
    if(out_intf->intf_nw_props.l2_mode == TRUNK && vlan_id > 0) {
      // tag it with vlan id
       
      ip_add_t next_ip;
      for(int i=0; ; i++){
        if(out_intf->intf_nw_props.vlan_id[i] == vlan_id) {
          strncpy(next_ip.ip_addr, out_intf->intf_nw_props.vlan_id_binded_ip[i].ip_addr, IP_LENGTH);
          break;
        }
      }
     
      arp_entry = arp_table_lookup(node, next_ip.ip_addr);
      if(arp_entry == NULL) {
        arp_entries_t *insane_arp_entry = init_insane_arp_entry(next_ip.ip_addr);
        vlan_eth_frame_t *vlan_frame = (vlan_eth_frame_t *)tag_eth_vlan(eth_frm, vlan_id, &pkt_size);
        append_to_arp_pending_list(insane_arp_entry, (char *)vlan_frame, protocol_number, pkt_size);
        add_entry_to_arp_table(node, insane_arp_entry); 

        send_arp_broadcast_msg_flood(node, next_ip.ip_addr, oif);
        return;      
      }
      
      if(arp_entry->is_sane == FALSE) {
      // append and return
        append_to_arp_pending_list(arp_entry, (char *)eth_frm, protocol_number, pkt_size);
      return;
      } 
     
      memcpy(eth_frm->dest_mac.mac_addr, arp_entry->mac_addr.mac_addr, MAC_LENGTH);
      
    // send pkt to next hop 
      pkt_size += ETH_HDR_SIZE_EXCL_PAYLOAD;
      send_pkt((char *)eth_frm, pkt_size, out_intf);
      return;   

    }


    interface_t *nbr_intf = get_nbr_node_intf(out_intf);
    arp_entry = arp_table_lookup(node, IF_IP(nbr_intf));
    if(arp_entry == NULL) {
      arp_entries_t *insane_arp_entry = init_insane_arp_entry(IF_IP(nbr_intf));
      // queue : fcfs
      append_to_arp_pending_list(insane_arp_entry, (char *)eth_frm, protocol_number, pkt_size);
      
      add_entry_to_arp_table(node, insane_arp_entry);      

      // have to wait for the arp msg arrival
    
      send_arp_broadcast_msg_flood(node, IF_IP(nbr_intf), oif);
      return;  
    }
    if(arp_entry->is_sane == FALSE) {
      // append and return

      append_to_arp_pending_list(arp_entry, (char *)eth_frm, protocol_number, pkt_size);
      return;
    } 
    //make pkt to make room for checksum
    memcpy(eth_frm->dest_mac.mac_addr, arp_entry->mac_addr.mac_addr, MAC_LENGTH);
    
    // send pkt to next hop 
    pkt_size += ETH_HDR_SIZE_EXCL_PAYLOAD;
    send_pkt((char *)eth_frm, pkt_size, out_intf);
    return;   
  }
  // 3. exact match
  promote_pkt_to_l3(node, 0, get_eth_hdr_payload(eth_frm), protocol_number, pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD);
  return;
}

void demote_pkt_to_l2(node_t *node, unsigned int nexthop_ip, char *pkt, unsigned int pkt_size, interface_t *oif, unsigned int protocol_number, unsigned int vlan_id){
   switch(protocol_number){
     case ETH_IP: {
       l2_forward_eth_ip_frm(node, nexthop_ip, pkt, pkt_size, oif, protocol_number, vlan_id);
     }
     default : break;
   }

};
