#include "./../CommandParser/libcli.h"
#include "./../CommandParser/cmdtlv.h"
#include "cmdcodes.h"
//#include "./../include/graph.h"
#include "./../include/hash.h"
#include <stdio.h>

extern ctrl_table_t *topo;
extern node_t *get_node_by_node_name(ctrl_table_t *graph, char* node_name);
extern void send_arp_broadcast_msg_flood(node_t *node, char *ip_addr,char *exclusive_if);
extern void dump_arp_entry(node_t *node);
extern void dump_mac_entry(node_t *node);
extern void dump_rt_table(node_t *node);
extern void set_default_gw_ip(node_t *node, char *ip_addr, unsigned int cost);
extern void bind_ip_with_vlan(node_t *intf, unsigned int vlan_id, char *ip_addr, char mask, unsigned int cost);
extern int get_node_intf_available_slot(node_t *node);
extern void ping(node_t *node, char *dest_ip);
extern interface_t* get_node_if_by_name(node_t *node, char*if_name);
extern void compute_spf_all_routers(ctrl_table_t *topo);
extern bool_t add_route_entry(node_t *router, char *dst, char mask, char *gw, interface_t* oif, unsigned char cost);
extern void show_spf_results(node_t *node);
extern void compute_spf(ctrl_table_t *topo, node_t *spf_root);
extern void mk_router_solicit_msg(node_t *node);
static int show_nw_topology_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

  switch(CMDCODE) {
    case CMDCODE_SHOW_NW_TOPOLOGY:
	    dump_nw_graph(topo);
	    break;
    default:
	    ;
  }
  return 0;
}

static int run_node_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);

  tlv_struct_t *tlv = NULL;
  char *node_name = NULL;
  char *ip_addr = NULL;
  node_t *snode;
  char *ping_dest_ip;

  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0) {
      node_name = tlv->value;
	}
	else if(strncmp(tlv->leaf_id, "ip_address", strlen("ip_address")) == 0) ip_addr = tlv->value;
	else if(strncmp(tlv->leaf_id, "ping_dest_ip", strlen("ping_dest_ip")+1) ==0) ping_dest_ip = tlv->value;
  }TLV_LOOP_END;

  switch(CMDCODE) {
    case CMDCODE_RUN_RESOLVE_ARP:
  snode = get_node_by_node_name(topo, node_name);
		send_arp_broadcast_msg_flood(snode, ip_addr, NULL);
		break;
    case CMDCODE_RUN_PING:
  snode = get_node_by_node_name(topo, node_name);
	    ping(snode, ping_dest_ip);
		break;
	case CMDCODE_RUN_SPF:
  snode = get_node_by_node_name(topo, node_name);
		compute_spf(topo, snode);
		break;
	case CMDCODE_RUN_SPF_ALL:
		compute_spf_all_routers(topo);
		break;
	case CMDCODE_RUN_SOLICIT:
		snode = get_node_by_node_name(topo, node_name);
		mk_router_solicit_msg(snode);
		break;
	default: break;
  }
  return 0;
}
/*
static int arp_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  
  tlv_struct_t *tlv = NULL;
  char *node_name = NULL;
  char *ip_addr = NULL;
  node_t *snode;

  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0) {
	node_name = tlv->value;
    } 
    else if(strncmp(tlv->leaf_id, "ip_address", strlen("ip_address")) == 0) {
	ip_addr = tlv->value;
    }
  }TLV_LOOP_END;
  switch(CMDCODE) {
    case CMDCODE_RUN_RESOLVE_ARP:
	    snode = get_node_by_node_name(topo, node_name);
	    send_arp_broadcast_msg_flood(snode, ip_addr, NULL);
	    break;
    default:
	    ;
  }
  return 0;	
};
*/
static int node_config_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char *dest_ip;
  char *gw_ip;
  char *oif;
  unsigned char cost;
  char mask;
  tlv_struct_t *tlv = NULL;
  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")+1) == 0) node_name = tlv->value;
	else if(strncmp(tlv->leaf_id, "dest_ip", strlen("dest_ip")+1) == 0) {
		dest_ip= tlv->value;
	} 
	else if(strncmp(tlv->leaf_id, "mask", strlen("mask") +1) == 0) {
		mask  = atoi(tlv->value);
	}
	else if(strncmp(tlv->leaf_id, "gw_ip", strlen("gw_ip") +1) == 0) {
	    gw_ip = tlv->value;
	}
	else if(strncmp(tlv->leaf_id, "oif", strlen("oif")+1) == 0) {
	    oif = tlv->value;
	}
	else if(strncmp(tlv->leaf_id, "cost", strlen("cost")+1) == 0) {
	    cost = atoi(tlv->value);
	}
  }TLV_LOOP_END;
	node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
	case CMDCODE_CONFIG_L3_TABLE:{
	  interface_t *out_if = get_node_if_by_name(node, oif);
	  if(add_route_entry(node, dest_ip, mask, gw_ip, out_if, cost)== TRUE) return 1;
	  return 0;
								 }
	default:
	  break;
  }
  return 0;
}
static int default_gw_config_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char *gw_ip;
  char gw_cost;
  tlv_struct_t *tlv = NULL;

  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0)
		node_name = tlv->value;
	else if(strncmp(tlv->leaf_id, "gw_ip", strlen("gw_ip")+1) == 0)
		gw_ip = tlv->value;
	else if(strncmp(tlv->leaf_id, "gw_cost", strlen("gw_cost")+1) == 0)
		gw_cost = atoi(tlv->value);
  }TLV_LOOP_END;
  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
    case CMDCODE_CONFIG_DEFAULT_GW:
	  set_default_gw_ip(node, gw_ip, gw_cost);
	  break;
	default:
	  break;
  }
  return 0;
}

static int bind_vlan_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char *vip;
  char vmask;
  char vcost;
  char vlan_id;
  tlv_struct_t *tlv = NULL;
  
  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0)
		node_name = tlv->value;
    else if(strncmp(tlv->leaf_id, "vip", strlen("vip")+1) == 0)
		vip = tlv->value;
	else if(strncmp(tlv->leaf_id, "vcost", strlen("vcost")+1) ==0)
		vcost = atoi(tlv->value);
	else if(strncmp(tlv->leaf_id, "vmask", strlen("vmask")+1) ==0)
		vmask = atoi(tlv->value);
	else if(strncmp(tlv->leaf_id, "vlan_id", strlen("vlan_id")+1) ==0)
		vlan_id = atoi(tlv->value);
  }TLV_LOOP_END;
  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
	  case CMDCODE_CONFIG_SVI:
		  bind_ip_with_vlan(node, vlan_id, vip, vmask, vcost);
		  break;
	  default:
		  break;
  }
  return 0;
}
/*
static int ping_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char *ping_dest_ip;
  tlv_struct_t *tlv=NULL;

  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")+1) == 0)
		node_name = tlv->value;
	else if(strncmp(tlv->leaf_id, "ping_dest_ip", strlen("ping_dest_ip")+1) ==0)
		ping_dest_ip = tlv->value;
  }TLV_LOOP_END;
  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
    case CMDCODE_RUN_PING:
	    ping(node, ping_dest_ip);
		break;
	default:
		break;
  }
  return 0;
}
*/
static int show_node_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;

  tlv_struct_t *tlv = NULL;
  
  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")) == 0 )
	    node_name = tlv->value;
  }TLV_LOOP_END;
  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
    case CMDCODE_SHOW_ARP_TABLE:
	    dump_arp_entry(node);
	    break;
	case CMDCODE_SHOW_MAC_TABLE:
		dump_mac_entry(node);
		break;
	case CMDCODE_SHOW_ROUTE_TABLE:
		dump_rt_table(node);		
		break;
	case CMDCODE_SHOW_SPF:
		show_spf_results(node);
    default: break;

  }
  return 0;
}
static int show_intf_stat_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char is_interface = 0;
  tlv_struct_t *tlv = NULL;
  TLV_LOOP_BEGIN(tlv_buf, tlv) {
	if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")+1) == 0)
		node_name = tlv->value;
  }TLV_LOOP_END;

  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
	case CMDCODE_SHOW_INTF_STAT: {
	  int until = get_node_intf_available_slot(node);
	  for(int i=0; i<until; i++) {
		unsigned int rx = node->if_list[i]->intf_nw_props.rx_counter;
		unsigned int tx = node->if_list[i]->intf_nw_props.tx_counter;
		printf("%s :: PktTx : %d , PktRx : %d\n",node->if_list[i]->name,tx, rx);
	  }
	  break;
	}
	default: break;							
  }
  return 0;
}
static void default_intf_config_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable) {
  int CMDCODE = -1;
  CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
  node_t *node;
  char *node_name;
  char *if_name;
  char *up_or_down;
  unsigned char cost_metric;

  tlv_struct_t *tlv = NULL;
  TLV_LOOP_BEGIN(tlv_buf, tlv) {
    if(strncmp(tlv->leaf_id, "node_name", strlen("node_name")+1) == 0)
			node_name = tlv->value;
	else if(strncmp(tlv->leaf_id, "interface", strlen("interface")+1) == 0)
		    if_name = tlv->value;
	else if(strncmp(tlv->leaf_id, "up_or_down", strlen("up_or_down")+1) == 0) up_or_down = tlv->value;
	else if(strncmp(tlv->leaf_id, "metric_val", strlen("metric_val")+1) == 0) cost_metric = atoi(tlv->value);
  }TLV_LOOP_END;

  bool_t is_up;
  if(strncmp(up_or_down, "up", strlen("up") +1) == 0) is_up = TRUE;
  else is_up = FALSE;
  node = get_node_by_node_name(topo, node_name);
  switch(CMDCODE) {
    case CMDCODE_CONFIG_UP: {
		interface_t *intf = get_node_if_by_name(node, if_name);
		intf->intf_nw_props.if_up = is_up; 
		break;
	}
	case CMDCODE_CONFIG_COST_METRIC: {
		interface_t *intf = get_node_if_by_name(node, if_name);
		intf->link->cost = cost_metric;
		break;
	}
	default : break;
  }
}
//always accept pointer to the given string
static int validate_node_name(char *value){
  node_t* found_node = get_node_by_node_name(topo, value);
  if(found_node == NULL) return VALIDATION_FAILED;
  return VALIDATION_SUCCESS; 
}
void nw_init_cli() {
  init_libcli();

  param_t *show = libcli_get_show_hook();
  param_t *debug = libcli_get_debug_hook();
  param_t *config = libcli_get_config_hook();
  param_t *run = libcli_get_run_hook(); 
  param_t *debug_show = libcli_get_debug_show_hook();
  param_t *root = libcli_get_root();

  {
    /* show topology */
    static param_t topology;
    init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID, 0, "Dump Complete Network Topology");
    libcli_register_param(show, &topology);
    set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
	
  
    static param_t node;
    init_param(&node, CMD, "node", 0, 0, INVALID, 0, "help");
    libcli_register_param(show, &node);
    {
	  static param_t node_name;

	  init_param(&node_name, LEAF, 0, 0, validate_node_name, STRING, "node_name", "Help : Node name");
	  libcli_register_param(&node, &node_name);
	  {
		static param_t interface;
		init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "show interface info");
		libcli_register_param(&node_name, &interface);
		{
		  static param_t statistics;
		  init_param(&statistics, CMD, "statistics", show_intf_stat_handler,0, INVALID, 0, "show interface statistics");
		  libcli_register_param(&interface, &statistics);
		  set_param_cmd_code(&statistics, CMDCODE_SHOW_INTF_STAT);
		}

	  }
	  {
	    static param_t arp;
	    init_param(&arp, CMD, "arp", show_node_handler, 0, INVALID , 0, "show arp table");
	    libcli_register_param(&node_name, &arp);
	    set_param_cmd_code(&arp, CMDCODE_SHOW_ARP_TABLE);
      }
	  {
        static param_t mac;
		init_param(&mac, CMD, "mac", show_node_handler, 0, INVALID, 0, "show mac table");
		libcli_register_param(&node_name, &mac);
		set_param_cmd_code(&mac, CMDCODE_SHOW_MAC_TABLE);
	  }
	  {
        static param_t route;
	    init_param(&route, CMD, "route", show_node_handler, 0, INVALID, 0, "show routing table");
		libcli_register_param(&node_name, &route);
		set_param_cmd_code(&route, CMDCODE_SHOW_ROUTE_TABLE);

	  }
	  {
		static param_t spf;
		init_param(&spf, CMD, "spf", show_node_handler, 0, INVALID, 0, "show spf result");
		libcli_register_param(&node_name, &spf);
		set_param_cmd_code(&spf, CMDCODE_SHOW_SPF);
	  }
    }	    	    
  }
  {
	/* config */
	static param_t node;
	init_param(&node, CMD, "node", 0, 0, INVALID, 0, "help");
	libcli_register_param(config, &node);
	{ 
	static param_t node_name;
	init_param(&node_name , LEAF, 0, 0, 0, STRING, "node_name", "node name");
	libcli_register_param(&node, &node_name);
	{
	  static param_t route;
	  init_param(&route, CMD, "route", 0, 0, INVALID, 0, "config routing table entry");
	  libcli_register_param(&node_name, &route);
	  {
	    static param_t dest_ip;
		init_param(&dest_ip, LEAF, 0, 0, 0, IPV4, "dest_ip", "destination ip");
		libcli_register_param(&route, &dest_ip);
		{
		  static param_t mask;
		  init_param(&mask, LEAF, 0, 0, 0, INT, "mask", "mask value");
		  libcli_register_param(&dest_ip, &mask);
		  {
			static param_t gw_ip;
			init_param(&gw_ip, LEAF, 0, 0, 0, IPV4, "gw_ip", "gateway ip addr");
			libcli_register_param(&mask, &gw_ip);
			{
			  static param_t oif;
			  init_param(&oif, LEAF, 0, 0, 0, STRING, "oif", "outgoing interface");
			  libcli_register_param(&gw_ip, &oif);
			  {
			    static param_t cost;
				init_param(&cost, LEAF, 0, node_config_handler, 0, INT, "cost", "cost metric");
				libcli_register_param(&oif, &cost);
				set_param_cmd_code(&cost, CMDCODE_CONFIG_L3_TABLE);
			  }
			}

		  }
		}
	  }
	  static param_t gw;
	  init_param(&gw, CMD, "gw", 0, 0, INVALID, 0, "config default gateway address");
	  libcli_register_param(&node_name, &gw);
	  {
	    static param_t gw_ip;
		init_param(&gw_ip, LEAF, 0, 0, 0, IPV4, "gw_ip", "gateway ip address");
		libcli_register_param(&gw, &gw_ip);
		{
		  static param_t gw_cost;
		  init_param(&gw_cost, LEAF, 0, default_gw_config_handler, 0, INT, "gw_cost", "cost to gateway");
		  libcli_register_param(&gw_ip, &gw_cost);
		  set_param_cmd_code(&gw_cost, CMDCODE_CONFIG_DEFAULT_GW);
		}
	  }
	  static param_t vip;
	  init_param(&vip, CMD, "vip", 0, 0, INVALID, 0, "config virtual ip address with vlan");
	  libcli_register_param(&node_name, &vip);
	  {
	    static param_t vmask;
		init_param(&vmask, LEAF, 0, 0, 0, INT, "vmask", "virtual ip mask value");
		libcli_register_param(&vip, &vmask);
		{
		  static param_t vcost;
		  init_param(&vcost, LEAF, 0, 0, 0, INT, "vcost", "virtual ip cost");
		  libcli_register_param(&vmask, &vcost);
		  {
			static param_t vlan_id;
			init_param(&vlan_id, LEAF, 0, bind_vlan_handler, 0, INT, "vlan_id", "bind ip with vlan id");
			libcli_register_param(&vcost, &vlan_id);
			set_param_cmd_code(&vlan_id, CMDCODE_CONFIG_SVI);
		  }
		}

	  }
	  static param_t interface;
	  init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "config Interface");
	  libcli_register_param(&node_name, &interface);
	  {
		static param_t if_name;
		init_param(&if_name, LEAF, 0, 0, 0, STRING, "if_name", "interface name to config");
		libcli_register_param(&interface, &if_name);
		{
		  static param_t up_or_down;
		  init_param(&up_or_down, LEAF, 0, default_intf_config_handler, 0, STRING, "up_or_down", "up or dwon");
		  libcli_register_param(&if_name, &up_or_down);
		  set_param_cmd_code(&up_or_down, CMDCODE_CONFIG_UP);
		}
		{
		  static param_t metric;
		  init_param(&metric, CMD, "metric", 0, 0, INVALID, 0, "config cost metric for interface");
		  libcli_register_param(&if_name, &metric);
		  {
			static param_t metric_val;
			init_param(&metric_val, LEAF, 0, default_intf_config_handler, 0, INT, "metric_val", "config cost metric for interface");
			libcli_register_param(&metric, &metric_val);
			set_param_cmd_code(&metric_val, CMDCODE_CONFIG_COST_METRIC);
		  }
		}
	  }
	}
	}

  }
  /* run */
  {
    static param_t node;
    init_param(&node, CMD, "node", 0, 0, INVALID, 0, "Help : node");
    libcli_register_param(run, &node);
    {
	static param_t node_name;
	init_param(&node_name, LEAF, 0, 0, validate_node_name, STRING, "node_name", "Help : Node name");
	libcli_register_param(&node, &node_name);
	{
		{
		static param_t solicit_msg;
		init_param(&solicit_msg, CMD, "solicit_msg", run_node_handler, 0, INVALID, 0, "make solicit message to adjacent router");
		libcli_register_param(&node_name, &solicit_msg);
		set_param_cmd_code(&solicit_msg, CMDCODE_RUN_SOLICIT);
		}
		static param_t resolve_arp;
		init_param(&resolve_arp, CMD, "resolve_arp", 0, 0, INVALID, 0, "Help : resolving arp : give ip address");
		libcli_register_param(&node_name, &resolve_arp);
		{
			static param_t ip_address;
			init_param(&ip_address, LEAF, 0, run_node_handler,0, IPV4, "ip_address", "Help : give ip address");
			libcli_register_param(&resolve_arp, &ip_address);
			set_param_cmd_code(&ip_address, CMDCODE_RUN_RESOLVE_ARP);
		}
		static param_t ping;
		init_param(&ping, CMD, "ping", 0, 0, INVALID, 0, "Help : run node <node name> ping <dest ip>");
		libcli_register_param(&node_name, &ping);
		{
			static param_t ping_dest_ip;
			init_param(&ping_dest_ip, LEAF, 0, run_node_handler,0, IPV4, "ping_dest_ip", "Help : give ip address");
			libcli_register_param(&ping, &ping_dest_ip);
			set_param_cmd_code(&ping_dest_ip, CMDCODE_RUN_PING);
		
		}
		static param_t spf;
		init_param(&spf, CMD, "spf", run_node_handler,0, INVALID, 0, "implementing shortest path first algorithm");
		libcli_register_param(&node_name, &spf);
		set_param_cmd_code(&spf, CMDCODE_RUN_SPF);
	}
	static param_t spf;
	init_param(&spf, CMD, "spf", 0, 0, INVALID, 0, "Help :run spf for all nodes in topology");
	libcli_register_param(run, &spf);
	{
      static param_t all;
	  init_param(&all, CMD, "all", run_node_handler,0, INVALID, 0, "implementing spf for all nodes");
	  libcli_register_param(&spf, &all);
	  set_param_cmd_code(&all, CMDCODE_RUN_SPF_ALL);
	}
    } 
  }
  support_cmd_negation(config);
}
