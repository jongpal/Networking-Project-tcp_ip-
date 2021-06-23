#ifndef __LAYER2__
#define __LAYER2__
// #include "./../net.h"
#include "utils.h"
#include "graph.h"
#include <stdint.h>
#include <time.h>
#define ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(eth_hdr_t) - sizeof(((eth_hdr_t *)0) -> payload))

#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(vlan_eth_frame_t) - sizeof(((vlan_eth_frame_t *)0)->payload))



#define INTF_NAME_SIZE 30

#define GET_802_1Q_VLAN_ID(vlan_hdr) vlan_hdr->vlan_id

// enum type {
//   GRAPH_T, //graph_elements_t -> graph_t
//   ARP_T, //arp_table_t -> ctrl_arp_table_t
//   MAC_T, //mac table
//   NODE_T, //node_t
//   ROUTER_T, 
// };

typedef struct graph_elements_ graph_elements_t;

typedef struct mac_entry {
  mac_add_t mac_addr; // key
  unsigned int vlan_id;
  char oif_name[INTF_NAME_SIZE]; 
  time_t issued_time; // aging time : 1hour : 60 * 60 = 3600 seconds
}mac_entry_t;

// typedef struct mac_table {
//   char is_entry;
//   mac_entry_t *entry;
// } mac_table_t;

// typedef struct mac_table_controller {
//   unsigned int table_size;
//   unsigned int curr_size;
//   mac_table_t *mac_table;
// } ctrl_mac_table_t;


typedef struct pending_requests {
  int protocol_number;
  unsigned int pkt_size;
  void *pkt;
  struct pending_requests *next_pd_pkt;
} arp_pending_entry_t;


typedef struct arp_pending_entry_head_tail {
  arp_pending_entry_t *head;
  arp_pending_entry_t *tail;
} arp_pd_list_head_tail_t;

typedef struct arp_entries {
  ip_add_t ip_addr; // key
  mac_add_t mac_addr;
  char oif_name[INTF_NAME_SIZE];
  bool_t is_sane;
  int pending_pkts_count;
  arp_pd_list_head_tail_t *arp_pd_list;
  //struct arp_entries *next; // possible ECMP : multiple outgoing route for one ip address
} arp_entries_t;

// typedef struct arp_table {
//   char is_entry;

//   arp_entries_t *entry;
// } arp_table_t;

// typedef struct table_generic_controller {
//   char topology_name[32];
//   unsigned int table_size;
//   unsigned int curr_size;
//   // union {
//   //   arp_table_t *arp_table;
//   //   mac_table_t *mac_table;
//   //   graph_elements_t *hash_graph;
//   // };
//   enum type table_type;
//   graph_elements_t *table_ptr;
// } ctrl_table_t;

#pragma pack (push,1)
typedef struct arp_hdr {
  uint16_t hw_type;
  uint16_t protocol_type;
  uint8_t hw_addr_len;
  uint8_t protocol_addr_len;
  uint16_t op_code;
  mac_add_t src_mac;
  uint32_t src_ip;
  mac_add_t dest_mac;
  uint32_t dest_ip;
} arp_hdr_t;
#pragma pack(pop)

#pragma pack (push,1)
typedef struct eth_frame {
  mac_add_t dest_mac;
  mac_add_t src_mac;
  uint16_t type;
  char payload[248];
  uint32_t crc;
} eth_hdr_t;
#pragma pack(pop)

#pragma pack (push,1)
typedef struct vlan_802_1q {
  uint16_t tpid;
  uint16_t pri :3;
  uint16_t cfi :1;
  uint16_t vlan_id : 12;
} vlan_802_1q_hdr_t;
#pragma pack(pop)

#pragma pack (push,1)
typedef struct vlan_tagged_eth_frame {
  mac_add_t dest_mac;
  mac_add_t src_mac;
  vlan_802_1q_hdr_t vlan_hdr;
  uint16_t type;
  char payload[248];
  uint32_t crc;
} vlan_eth_frame_t;
#pragma pack(pop)

#define ETH_HDR_SIZE_BEFORE_PAYLOAD (unsigned int)&((eth_hdr_t *)0)->payload
// #define GET_DEST_IP_FROM_ARP_HDR (unsigned int)
// *(unsigned int *)
#define ETH_CRC(eth_hdr_ptr, payload_size) (*(unsigned int *)(((char *)(((eth_hdr_t *)eth_hdr_ptr)->payload) + payload_size)))

#define VLAN_ETH_CRC(vlan_eth_frame_ptr, payload_size)  (*(unsigned int *)(((char *)(((vlan_eth_frame_t *)vlan_eth_frame_ptr)->payload) + payload_size)))
//should be revised ? about memory usage
//pkt 전, 후로 공간 분배
// static eth_hdr_t* alloc_eth_hdr_with_payload(char *pkt, unsigned int pkt_size);


// static bool_t is_intf_qualified_receiver (interface_t *interface, eth_hdr_t *ethernet_header);

void send_arp_broadcast_msg_flood(node_t *node, char *ip_addr, char *exemptive_if);
void send_arp_broadcast_msg_excl(node_t *node, char *ip_addr, char* oif, unsigned int vlan_id);

void send_arp_reply(interface_t *iif, eth_hdr_t *recvd_eth);
void process_arp_reply(interface_t *iif, arp_hdr_t *arp_to_add);
void process_arp_broadcast(interface_t * iif, eth_hdr_t* recvd_eth, unsigned int pkt_size);
void init_arp_table(node_t *node);
void init_mac_table(node_t *node);
arp_entries_t *arp_table_lookup(node_t *node, char *ip_addr);

bool_t delete_arp_entry(node_t *node, char *ip_addr);
bool_t add_entry_to_arp_table(node_t *node, arp_entries_t* arp_entry);
bool_t update_arp_entry(node_t *node, arp_hdr_t *arp_hdr, interface_t *iif);
void dump_arp_entry(node_t *node);
void free_arp_table(node_t *node);

void add_mac_entry(node_t* node, mac_add_t *mac_addr, char *intf_name, unsigned int vlan_id);

bool_t delete_mac_entry(node_t* node, mac_add_t* mac_addr);

mac_entry_t *mac_table_lookup(node_t* node, char* mac_addr);
void dump_mac_entry(node_t *node);

void l2_recv_frame(node_t *node, char *intf_name, char *data, unsigned int data_size);

void pkt_dump(eth_hdr_t* eth_pkt, unsigned int pkt_size);


//didn't check yet
static vlan_802_1q_hdr_t* get_vlan_hdr_from_pkt(eth_hdr_t *eth_hdr) {

  // vlan_802_1q_hdr_t 's tpid field is 2 Bytes ( so is type field in normal ethernet header)
  
  if(eth_hdr->type == 0x8100) return &(((vlan_eth_frame_t *)eth_hdr)->vlan_hdr);
  return NULL;
}

static char* get_eth_hdr_payload(eth_hdr_t *eth_hdr) {
  if(get_vlan_hdr_from_pkt(eth_hdr) != NULL) {
    return ((vlan_eth_frame_t *) eth_hdr)->payload;
  }
  return eth_hdr->payload;
}
unsigned int get_access_intf_vlan_id(interface_t *intf);

bool_t
is_trunk_interface_vlan_enabled(interface_t *intf, unsigned int vlan_id);

// vlan_eth_frame_t* tag_eth_vlan(eth_hdr_t *eth_hdr, unsigned int vlan_id, unsigned int *packet_size);
char* tag_eth_vlan(eth_hdr_t *eth_hdr, unsigned int vlan_id, unsigned int *packet_size);

static void promote_pkt_to_l2(node_t *node, interface_t *iif, eth_hdr_t *pkt, unsigned int data_size);
// static unsigned int GEN_ETH_HDR_SIZE_EXCL_PAYLOAD (eth_hdr_t *eth_hdr) {
//   vlan_802_1q_hdr_t *vlan_hdr = get_vlan_hdr(eth_hdr);
//   // NULL for normal eth_hdr without vlan_hdr
//   if(!vlan_hdr){
//     return ETH_HDR_SIZE_EXCL_PAYLOAD;
//   }
//   return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
  
// }
// #define GEN_ETH_HDR_SIZE_EXCL_PAYLOAD (get_vlan_hdr(eth_hdr_ptr) ? VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD : ETH_HDR_SIZE_EXCL_PAYLOAD

// #define GEN_ETH_CRC(eth_hdr_ptr, payload_size) (get_vlan_hdr(eth_hdr_ptr) ? VLAN_ETH_CRC(eth_hdr_ptr, payload_size) : ETH_CRC(eth_hdr_ptr, payload_size))
// static unsigned int GEN_ETH_CRC (eth_hdr_t *eth_hdr, unsigned int payload_size){
//   uint32_t crc;
//   if(get_vlan_hdr(eth_hdr)) {
//     crc = *(((vlan_eth_frame_t *)eth_hdr)->payload+payload_size);
//     // crc = VLAN_ETH_CRC(eth_hdr, payload_size);
//     return crc;
//   } else {
//     // crc = ETH_CRC(eth_hdr, payload_size);
//     crc = *(eth_hdr->payload+payload_size);
//     return crc;
//   }
// }

bool_t check_checksum(eth_hdr_t *pkt, unsigned int data_size);

void set_stp(ctrl_table_t *topo);

void demote_pkt_to_l2(node_t *node, unsigned int nexthop_ip, char *pkt, unsigned int pkt_size, interface_t *oif, unsigned int protocol_number, unsigned int vlan_id);


#endif
