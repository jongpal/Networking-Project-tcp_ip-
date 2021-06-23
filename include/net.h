#ifndef __NET__
#define __NET__
#include <stdint.h>
typedef enum{ FALSE, TRUE } bool_t;
typedef enum{ ACCESS = 1, TRUNK = 2, UNDEFINED = 3} l2_mode_t;
typedef enum{ ROOT = 1, DESIGNATED = 2, BLOCKED = 3, UNDEF = 4 } port_mode_t;
#define MAX_VLAN_CONFIG 3
typedef struct node_ node_t;
typedef struct interface_ interface_t;
typedef struct arp_table_controller ctrl_arp_table_t;
typedef struct mac_table_controller ctrl_mac_table_t;
typedef struct table_generic_controller ctrl_table_t;
typedef struct route_node_head_tail rt_ht;
typedef struct route_table_entry rt_entry_t;

#define MAC_LENGTH 6
#define IP_LENGTH 16

typedef struct ip_add_ {
  // A.B.C.D => 15 characters + '\0'
  char ip_addr[IP_LENGTH];
} ip_add_t;

//mac address 8 번째 비트 : 0 : Unicast, 1 : Multicast
//First 6digits(3bytes) : identifies manufacturer
typedef struct mac_add_ {
  // XX:XX:XX:XX:XX:XX (base 16) 48bits -> 6 bytes
  // 여기서 : 생략된 형태로 저장 (broadcast mask 용이하게 하기위해)
  unsigned char mac_addr[MAC_LENGTH];

} mac_add_t;

typedef struct vlan_t {
  unsigned int vlan_id;
  ip_add_t binded_ip_addr;
  struct vlan_t *next;
} vlan_id_t;

typedef struct bridge_id_format {
  uint16_t bridge_priority : 4;
  uint16_t vlan_number : 12;
  uint8_t mac[MAC_LENGTH];
} bid_t;

typedef struct stp_info {
  bid_t self_bid;
  bid_t loc_rootid[8];
  unsigned int path_cost_to_root;
} stp_infos_t;

typedef struct bpdu_ {
  uint16_t protocol_id;
  uint8_t version;
  uint8_t message_type;
  uint8_t flags;

  bid_t root_id;
  uint32_t cost_of_path;
  bid_t bridge_id;
  uint16_t port_id;

  uint16_t message_age;
  uint16_t max_age;
  uint16_t hello_time;
  uint16_t forward_delay;
} bpdu_t;



typedef struct node_nw_props_{
  bool_t is_lb_addr;
  ip_add_t lb_add;
  mac_add_t base_mac;
  ctrl_table_t *ctr_mac_table;
  ctrl_table_t *ctr_arp_table;
  rt_ht *rt_table_manager;
  ip_add_t default_gw;
  //spt
  stp_infos_t stp_infos[MAX_VLAN_CONFIG];
  // for foreign agent( 방문 에이전트 )
  // ip_add_t COA[IP_LENGTH];

  bool_t is_mobile_node; // record coa router address
  ip_add_t solicit_addr;
  ip_add_t home_agent_addr;
  union {
    ip_add_t coa;// for foreign agent's binding info
    ip_add_t router_address;// for mobile node's connected router info
  };
  
  uint32_t router_pref_level; 

  bool_t is_foreign_agent; // coa- mobile_node_ip mapping
  ip_add_t mobile_node_ip;

  // bool_t is_home_agent;
  // ctrl_table_t *hlr; // managing Home Location Register 
} node_nw_props_t;

// typedef struct mobile_node {
//   node_nw_props_t node_nw_props;
//   ip_add_t home_agent_addr;
//   //coa
//   ip_add_t coa[IP_LENGTH];
//   uint32_t coa_pref_level;
// } mobile_node_nw_props_t;

// void init_node_nw_props(node_nw_props_t *node_nw_props);
void init_node_nw_props(node_t *node);

typedef struct intf_nw_props_ {
  bool_t if_up; //interface disabled ?
  // Rx, Tx statistics
  unsigned int rx_counter;
  unsigned int tx_counter;
  // L2
  mac_add_t mac_add;
  // L3
  // interface may or may not has ip address
  bool_t is_ip_config;
  ip_add_t ip_add;
  l2_mode_t l2_mode;
  unsigned int vlan_id[MAX_VLAN_CONFIG];
  bool_t is_svi_config;
  ip_add_t vlan_id_binded_ip[MAX_VLAN_CONFIG];
  
  //for host
  char solicitation_addr[IP_LENGTH];
  //for router
  char advertise : 1;
  unsigned int preference_level;
  //spt
  port_mode_t port_type;
  char mask;
} intf_nw_props_t;

typedef struct foreign_agent_visitor_location_register_entry {
  //mobile node's
  mac_add_t mobile_mac;
  ip_add_t mobile_ip;

  uint16_t udp_src_port;
  ip_add_t home_agent_addr;
  
  uint64_t identification;
  uint16_t requested_registration_lifetime;
  uint16_t curr_registration_remained_lifetime;
} fa_vlr_entry_t;

void init_intf_nw_props(intf_nw_props_t *intf_nw_props);

#define IF_SOLICITATION_ADDR(intf_ptr) ((intf_ptr) -> intf_nw_props.solicitation_addr)

#define IF_MAC(intf_ptr) ((intf_ptr) -> intf_nw_props.mac_add.mac_addr)
#define IF_IP(intf_ptr) ((intf_ptr) -> intf_nw_props.ip_add.ip_addr)
#define IS_IF_UP(intf_ptr) ((intf_ptr)-> intf_nw_props.if_up == TRUE)
#define NODE_LO_ADDR(node_ptr) ((node_ptr) -> node_nw_props.lb_add.ip_addr)

// if interface has ip address, then this interface can operate on L3 mode
#define IS_INTF_L3_MODE(intf_ptr) ((intf_ptr) -> intf_nw_props.is_ip_config == TRUE)

bool_t node_set_loopback_address(node_t *node, char *ip_addr);
bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask);
bool_t node_unset_intf_ip_address(node_t *node, char *local_if);
void node_intf_set_l2_mode(node_t *node, char *intf_name, l2_mode_t mode);
void node_intf_set_vlanid(node_t *node, char *intf_name, unsigned int vlan_id);
char *get_string_from_l2_mode(l2_mode_t l2_mode);
void interface_assign_mac_address (interface_t *interface);
unsigned int convert_ip_from_str_to_int(char *ip_addr);
void convert_ip_from_int_to_str(unsigned int ip_addr, char *output_buffer);
interface_t* node_get_matching_subnet_interface(node_t *node, char *ip_addr);

unsigned int ip_addr_p_to_n(char *ip_addr);
void ip_addr_n_to_p(unsigned int ip_addr, char* ip_add_str);



void free_nw_graph(ctrl_table_t* graph);
void dump_nw_graph(ctrl_table_t* graph);

bool_t is_interface_l3_bidirectional(interface_t *interface);
#endif
