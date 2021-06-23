#ifndef __LAYER3_H__
#define __LAYER3_H__
#include "hash.h"
#include "tcpconst.h"
#include "layer4.h"

#define IP_HDR_LEN_IN_BYTES(ip_hdr_ptr) (ip_hdr_ptr->IHL)*4
#define IP_HDR_TOT_LEN_IN_BYTES(ip_hdr_ptr) (ip_hdr->tot_length)*4
#define CHAR_IP_HDR_PTR_TO_PAYLOAD(ip_hdr_ptr) ((char*)ip_hdr_ptr)+(ip_hdr_ptr->IHL)*4
#define IP_HDR_PAYLOAD_SIZE(ip_hdr_ptr) (ip_hdr->tot_length)*4 - (ip_hdr_ptr->IHL)*4
#define ICMP_ECHO_MSG_PTR_TO_PAYLOAD(echo_msg_t) ((char *)echo_msg_t)+8


#pragma pack(push, 1)
typedef struct ip_hdr {
  uint8_t version:4;
  uint8_t IHL:4;
  uint8_t type_of_service;
  uint16_t tot_length;

  uint16_t identification;
  uint16_t unused_flag:1;
  uint16_t DF_flag:1;
  uint16_t MORE_flag:1;
  uint16_t frag_offset : 13;

  uint8_t ttl;
  uint8_t protocol;
  uint16_t ip_hdr_checksum;

  uint32_t src_ip;
  uint32_t dest_ip;
}ip_hdr_t;
#pragma pack(pop)


// typedef struct hlr_entry {
//   ip_add_t mobile_ip; 
//   ip_add_t coa;
//   char oif[IF_NAME_SIZE];
//   char mask;
// } hlr_entry_t;
typedef struct nexthop_ {
  char gw_ip[16];
  interface_t *oif;
  uint32_t ref_count;
}nexthop_t;


typedef struct route_table_entry {
  char dest_ip[16];
  char mask;
  bool_t is_direct; // gw ip, oif
  // bool_t is_default_gw;
//  char gw_ip[16];
//  char oif[IF_NAME_SIZE];
  nexthop_t *nxt_hops[MAX_NXT_HOPS];
  unsigned char cost_metric;
  int nxthop_idx;
  int cur_ecmp_num;

  //for SVI(Switch Virtual Interface)
  bool_t is_svi_configured;
  unsigned int svi_vlan_id;

  bool_t is_coa_configured;
  ip_add_t coa;
} rt_entry_t;

typedef struct route_node {
  char key;// mask value
  ctrl_table_t *rt_table;
  struct route_node *prev;
  struct route_node *next;
} route_node;

typedef struct route_node_head_tail {
  struct route_node *head;
  struct route_node *tail;
} rt_ht; 

#pragma pack(push, 1)
typedef struct ping_msg_format {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_num;
} ICMP_ping_msg_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct router_solicitation_msg_format {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t reserved;
} router_solicit_msg_t;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct router_discovery_msg_basic_format {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t num_addrs;
  uint8_t addr_entry_size;
  uint16_t lifetime;
} router_discovery_basic_msg_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct router_discovery_msg_entry_format {
  uint32_t router_addr;
  uint32_t preference_level;
} router_discovery_entry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct mobile_ip_registration_request_msg {
  uint8_t type;
  uint8_t S : 1;
  uint8_t B : 1;
  uint8_t D : 1;
  uint8_t M : 1;
  uint8_t G : 1;
  uint8_t r : 1;
  uint8_t T : 1;
  uint8_t x : 1;
  // uint8_t code;
  uint16_t lifetime;
  uint32_t home_addr;
  uint32_t home_agent_addr;
  uint32_t coa;
  uint64_t identification;
} mbl_ip_register_req_msg_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct mobile_ip_registration_reply_msg {
  uint8_t type;
  uint8_t code;
  uint16_t lifetime;
  uint32_t home_addr;
  uint32_t home_agent_addr;
  uint64_t identification;
} mbl_ip_register_reply_msg_t;
#pragma pack(pop)


void init_route_table(node_t *node);
rt_entry_t* add_route_entry(node_t *router, char *dst, char mask, char *gw, interface_t *oif, unsigned char cost);
void dump_rt_table(node_t *rt);
void init_ip_hdr_default(ip_hdr_t *ip_hdr);

rt_entry_t *lookup_rt_table(node_t *rt, unsigned int dest_ip);
bool_t delete_rt_table_entry(node_t *rt, unsigned int dest_ip, char mask);

void demote_pkt_to_l3(node_t *node, char *data, unsigned int data_size, int protocol_number, unsigned int dest_ip_address);

void promote_pkt_to_l3(node_t *node, interface_t *recv_intf, char *payload, int protocol_number, unsigned int payload_size);

void mk_router_solicit_msg(node_t *mobile_node);
void mk_ping_echo_msg(node_t *host_node, char *payload, unsigned int* msg_size, char echo_msg_type);

void set_default_gw_ip(node_t *node, char *ip_addr, unsigned int cost);
void bind_ip_with_vlan(node_t *intf, unsigned int vlan_id, char *ip_addr, char mask, unsigned int cost);

#endif
