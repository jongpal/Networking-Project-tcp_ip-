#include "../include/hash.h"
#include "../include/communication.h"
#define IP_HOST_MULTICAST_ADDR "224.0.0.2"

extern void set_default_gw_ip(node_t *node, char *ip_addr, unsigned int cost);
extern void bind_ip_with_vlan(node_t *intf, unsigned int vlan_id, char *ip_addr, char mask, unsigned int cost);

ctrl_table_t *route_construction_test_topo() {
  ctrl_table_t *topo = create_new_graph("route_construction_test_topo");
  node_t *R1 = create_graph_node(topo, "R1");
  node_t *R2 = create_graph_node(topo, "R2");
  node_t *R3 = create_graph_node(topo, "R3");
  node_t *R4 = create_graph_node(topo, "R4");

  insert_link(R1, R2, "eth0/0", "eth0/1", 1);
  insert_link(R2, R3, "eth0/2", "eth0/3", 6);
  insert_link(R3, R4, "eth0/4", "eth0/5", 5);
  insert_link(R4, R1, "eth0/6", "eth0/7", 2);

  node_set_intf_ip_address(R1, "eth0/0", "10.1.1.1", 24);
  node_set_intf_ip_address(R2, "eth0/1", "10.1.1.2", 24);
  node_set_intf_ip_address(R2, "eth0/2", "11.1.1.1", 24);
  node_set_intf_ip_address(R3, "eth0/3", "11.1.1.2", 24);
  node_set_intf_ip_address(R3, "eth0/4", "12.1.1.1", 24);
  node_set_intf_ip_address(R4, "eth0/5", "12.1.1.2", 24);
  node_set_intf_ip_address(R4, "eth0/6", "13.1.1.1", 24);
  node_set_intf_ip_address(R1, "eth0/7", "13.1.1.2", 24);

  node_set_loopback_address(R1, "122.1.1.1");
  node_set_loopback_address(R2, "122.1.1.2");
  node_set_loopback_address(R3, "122.1.1.3");
  node_set_loopback_address(R4, "122.1.1.4");


  start_pkt_receiver_thread(topo);
  return topo; 
}

ctrl_table_t *inter_vlan_topo() {

  ctrl_table_t *topo = create_new_graph("inter vlan topo");
  node_t *hostA = create_graph_node(topo, "hostA");
  node_t *hostB = create_graph_node(topo, "hostB");
  node_t *hostC = create_graph_node(topo, "hostC");
  node_t *sw1 = create_graph_node(topo, "sw1");
  node_t *router1 = create_graph_node(topo, "router1");
  node_t *router2 = create_graph_node(topo, "router2");

  insert_link(hostA, sw1, "eth0/1", "eth2/1", 1);
  insert_link(hostB, sw1, "eth1/1", "eth2/2", 1);
  insert_link(router1, sw1, "eth3/1", "eth2/3", 1);
  insert_link(router2, router1, "eth4/1", "eth3/2", 1);
  insert_link(hostC, router2, "eth5/1", "eth4/2", 1);

  node_set_intf_ip_address(hostA, "eth0/1", "10.1.1.1", 24);
  node_set_intf_ip_address(hostB, "eth1/1", "11.1.1.1", 24);
  node_set_intf_ip_address(hostC, "eth5/1", "30.1.1.2", 24);
  node_set_intf_ip_address(router2, "eth4/2", "30.1.1.1", 24);
  node_set_intf_ip_address(router2, "eth4/1", "20.1.1.2", 24);
  node_set_intf_ip_address(router1, "eth3/2", "20.1.1.1", 24);

  node_intf_set_l2_mode(sw1, "eth2/1", ACCESS);
  node_intf_set_vlanid(sw1, "eth2/1", 11);
  node_intf_set_l2_mode(sw1, "eth2/2", ACCESS);
  node_intf_set_vlanid(sw1, "eth2/2", 12);
  node_intf_set_l2_mode(sw1, "eth2/3", TRUNK);
  node_intf_set_vlanid(sw1, "eth2/3", 11);
  node_intf_set_vlanid(sw1, "eth2/3", 12);

  node_intf_set_l2_mode(router1, "eth3/1", TRUNK);
  node_intf_set_vlanid(router1, "eth3/1", 11);
  node_intf_set_vlanid(router1, "eth3/1", 12);

  set_default_gw_ip(hostA, "10.1.1.8", 1); 
  set_default_gw_ip(hostB, "11.1.1.8", 1);
  set_default_gw_ip(hostC, "30.1.1.1", 1);

  bind_ip_with_vlan(router1, 11, "10.1.1.8", 24, 1); 
  bind_ip_with_vlan(router1, 12, "11.1.1.8", 24, 1);

  start_pkt_receiver_thread(topo);
  return topo; 
}

ctrl_table_t *mobile_ip_topo() {
  ctrl_table_t *topo = create_new_graph("mobile ip topo");
  node_t *home_agent = create_graph_node(topo, "home_agent");
  node_t *sender_agent = create_graph_node(topo, "sender_agent");
  node_t *R1 = create_graph_node(topo, "R1");
  node_t *R2 = create_graph_node(topo, "R2");
  node_t *anchor_visit_agent = create_graph_node(topo, "anchor_visit_agent");
  node_t *mobile_node = create_graph_node(topo, "mobile_node");

  insert_link(home_agent, R1, "eth0/1", "eth0/2", 1);
  insert_link(R1, sender_agent, "eth0/3", "eth0/4", 1);
  insert_link(home_agent, R2, "eth0/5", "eth0/6", 1);
  insert_link(R2, anchor_visit_agent, "eth0/7", "eth0/8", 1);
  insert_link(anchor_visit_agent, mobile_node, "eth0/9", "eth0/10", 1);
  
  node_set_intf_ip_address(home_agent, "eth0/1", "128.119.40.0", 24);
  node_set_intf_ip_address(R1, "eth0/2", "128.119.40.2", 24);
  node_set_intf_ip_address(R1, "eth0/3", "10.1.1.2", 24);
  node_set_intf_ip_address(sender_agent, "eth0/4", "10.1.1.1", 24);
  node_set_intf_ip_address(home_agent, "eth0/5", "128.119.41.1", 24);
  node_set_intf_ip_address(R2, "eth0/6", "128.119.41.2", 24);
  node_set_intf_ip_address(R2, "eth0/7", "79.119.41.3", 24);
  node_set_intf_ip_address(anchor_visit_agent, "eth0/8", "79.119.41.2", 24);
  node_set_intf_ip_address(anchor_visit_agent, "eth0/9","79.119.42.2", 24); // mobile_node 와 다른데 연결되어있다
  node_set_intf_ip_address(mobile_node, "eth0/10", "79.119.42.3", 24); // mobile node's permanent address
  // node_set_intf_ip_address(mobile_node, "eth0/10", "128.119.40.186", 24); // mobile node's permanent address
  node_set_loopback_address(mobile_node, "128.119.40.186");
  // node_set_loopback_address(mobile_node, "128.119.40.186");
    node_set_loopback_address(anchor_visit_agent, "122.1.1.2");
  node_set_loopback_address(home_agent, "122.1.1.1");
  node_set_loopback_address(R2, "122.1.1.3");
  node_set_loopback_address(R1, "122.1.1.4");
  node_set_loopback_address(sender_agent, "122.1.1.5");
  //set eth0/9 advertising interface 
  interface_t *anchor_intf = get_node_if_by_name(anchor_visit_agent, "eth0/9");
  anchor_intf->intf_nw_props.advertise = 1;

  mobile_node->node_nw_props.is_mobile_node = TRUE;
  memcpy(mobile_node->node_nw_props.solicit_addr.ip_addr, IP_HOST_MULTICAST_ADDR, IP_LENGTH);
  memcpy(mobile_node->node_nw_props.home_agent_addr.ip_addr, "128.119.40.0", IP_LENGTH);

  start_pkt_receiver_thread(topo);
  return topo; 
}

ctrl_table_t * linear_3_node_topo() {
  ctrl_table_t *topo = create_new_graph("l3 simple topo");
  node_t* R1 = create_graph_node(topo, "R1");
  node_t* R2 = create_graph_node(topo, "R2");
  node_t* R3 = create_graph_node(topo, "R3");
  node_t* R4 = create_graph_node(topo, "R4");

  insert_link(R1, R2, "eth0/1", "eth0/2", 1);
  insert_link(R2, R3, "eth0/3", "eth0/4", 1);
  insert_link(R3, R4, "eth0/5", "eth0/6", 1);

  node_set_loopback_address(R1, "122.1.1.1");
  node_set_loopback_address(R2, "122.1.1.2");
  node_set_loopback_address(R3, "122.1.1.3");
  node_set_loopback_address(R4, "122.1.1.4");

  node_set_intf_ip_address(R1, "eth0/1", "10.1.1.1", 24);
  node_set_intf_ip_address(R2, "eth0/2", "10.1.1.2", 24);
  node_set_intf_ip_address(R2, "eth0/3", "11.1.1.1", 24);
  node_set_intf_ip_address(R3, "eth0/4", "11.1.1.2", 24);
  node_set_intf_ip_address(R3, "eth0/5", "122.1.1.7", 24);
  node_set_intf_ip_address(R4, "eth0/6", "122.1.1.8", 24);
  
  start_pkt_receiver_thread(topo);
  return topo;
}

ctrl_table_t * L2_loop_topo() {
  ctrl_table_t *topo = create_new_graph("l2 loop topo");
  node_t *H1_end_device = create_graph_node(topo, "H1_end_device");
  node_t *H2_end_device = create_graph_node(topo, "H2_end_device");
  node_t *sw3 = create_graph_node(topo, "sw3");
  node_t *sw4 = create_graph_node(topo, "sw4"); 

  node_t *sw1 = create_graph_node(topo, "sw1");
  node_t *sw2 = create_graph_node(topo, "sw2"); 

  insert_link(H1_end_device, sw1, "eth0/1", "eth0/2", 1);
  insert_link(sw1, sw2, "eth0/5", "eth0/7", 1);
  insert_link(sw1, sw4, "eth0/8", "eth0/3", 1);
  insert_link(sw4, sw3, "eth0/4", "eth0/9", 1);
  insert_link(sw3, sw2, "eth0/10", "eth0/11", 1);
  insert_link(sw2, H2_end_device, "eth0/12", "eth0/13", 1);

  node_set_loopback_address(H1_end_device, "122.1.1.1");
  node_set_intf_ip_address(H1_end_device, "eth0/1", "10.1.1.1", 24);
  
  node_set_loopback_address(H2_end_device, "122.1.1.2");
  node_set_intf_ip_address(H2_end_device, "eth0/13", "10.1.1.2", 24);

  node_intf_set_l2_mode(sw1, "eth0/2", ACCESS);
  node_intf_set_vlanid(sw1, "eth0/2", 10);
  node_intf_set_l2_mode(sw1, "eth0/5", TRUNK);
  node_intf_set_vlanid(sw1, "eth0/5", 10);
  node_intf_set_l2_mode(sw1, "eth0/8", TRUNK);
  node_intf_set_vlanid(sw1, "eth0/8", 10);

  node_intf_set_l2_mode(sw2, "eth0/7", TRUNK);
  node_intf_set_vlanid(sw2, "eth0/7", 10);
  node_intf_set_l2_mode(sw2, "eth0/11", TRUNK);
  node_intf_set_vlanid(sw2, "eth0/11", 10);
  node_intf_set_l2_mode(sw2, "eth0/12", ACCESS);
  node_intf_set_vlanid(sw2, "eth0/12", 10);
  
  node_intf_set_l2_mode(sw3, "eth0/10", TRUNK);
  node_intf_set_vlanid(sw3, "eth0/10", 10);
  node_intf_set_l2_mode(sw3, "eth0/9", TRUNK);
  node_intf_set_vlanid(sw3, "eth0/9", 10);
  
  node_intf_set_l2_mode(sw4, "eth0/4", TRUNK);
  node_intf_set_vlanid(sw4, "eth0/4", 10);
  node_intf_set_l2_mode(sw4, "eth0/3", TRUNK);
  node_intf_set_vlanid(sw4, "eth0/3", 10);

  // set_node_spt_mode(node);


  start_pkt_receiver_thread(topo);
  return topo;
}
ctrl_table_t *
build_dual_switch_topo(){
  ctrl_table_t *topo = create_new_graph("dual switch graph 6 end");
  
  node_t *H1_end_device = create_graph_node(topo, "H1_end_device");
  node_t *H2_end_device = create_graph_node(topo, "H2_end_device");
  node_t *H3_end_device = create_graph_node(topo, "H3_end_device");
  node_t *H4_end_device = create_graph_node(topo, "H4_end_device");
  node_t *H5_end_device = create_graph_node(topo, "H5_end_device");
  node_t *H6_end_device = create_graph_node(topo, "H6_end_device");
  node_t *sw1 = create_graph_node(topo, "sw1");
  node_t *sw2 = create_graph_node(topo, "sw2");

  insert_link(H1_end_device, sw1, "eth0/1", "eth0/2", 1);
  insert_link(H2_end_device, sw1, "eth0/3", "eth0/7", 1);
  insert_link(H3_end_device, sw1, "eth0/4", "eth0/6", 1);
  insert_link(H4_end_device, sw2, "eth0/11", "eth0/12", 1);
  insert_link(H5_end_device, sw2, "eth0/8", "eth0/9", 1);
  insert_link(H6_end_device, sw2, "eth0/14", "eth0/10", 1);
  insert_link(sw1, sw2, "eth0/5","eth0/13", 1);

  node_set_loopback_address(H1_end_device, "122.1.1.1");
  node_set_intf_ip_address(H1_end_device, "eth0/1", "10.1.1.1", 24);
  node_set_loopback_address(H2_end_device, "122.1.1.2");
  node_set_intf_ip_address(H2_end_device, "eth0/3", "10.1.1.2", 24);
  node_set_loopback_address(H3_end_device, "122.1.1.3");
  node_set_intf_ip_address(H3_end_device, "eth0/4", "10.1.1.3", 24);
  node_set_loopback_address(H4_end_device, "122.1.1.4");
  node_set_intf_ip_address(H4_end_device, "eth0/11", "10.1.1.4", 24);
  node_set_loopback_address(H5_end_device, "122.1.1.5");
  node_set_intf_ip_address(H5_end_device, "eth0/8", "10.1.1.5", 24);
  node_set_loopback_address(H6_end_device, "122.1.1.6");
  node_set_intf_ip_address(H6_end_device, "eth0/14", "10.1.1.6", 24);

  node_intf_set_l2_mode(sw1, "eth0/2", ACCESS);
  node_intf_set_vlanid(sw1, "eth0/2", 10);

  node_intf_set_l2_mode(sw1, "eth0/6", ACCESS);
  node_intf_set_vlanid(sw1, "eth0/6", 11);
  
  node_intf_set_l2_mode(sw1, "eth0/7", ACCESS);
  node_intf_set_vlanid(sw1,"eth0/7", 10);

  node_intf_set_l2_mode(sw1, "eth0/5", TRUNK);
  node_intf_set_vlanid(sw1, "eth0/5", 10);
  node_intf_set_vlanid(sw1, "eth0/5", 11);

  node_intf_set_l2_mode(sw2, "eth0/13", TRUNK);
  node_intf_set_vlanid(sw2,"eth0/13", 10);
  node_intf_set_vlanid(sw2,"eth0/13", 11);

  node_intf_set_l2_mode(sw2, "eth0/9", ACCESS);
  node_intf_set_vlanid(sw2,"eth0/9", 10);

  node_intf_set_l2_mode(sw2, "eth0/12", ACCESS);
  node_intf_set_vlanid(sw2, "eth0/12", 11);

  node_intf_set_l2_mode(sw2, "eth0/10", ACCESS);
  node_intf_set_vlanid(sw2,"eth0/10", 10);

  start_pkt_receiver_thread(topo);
  
  return topo;
}







ctrl_table_t *build_l2_switch_topo(){
  //assuming end/host device have no idea about VLAN
  ctrl_table_t *topo = create_new_graph("l2 switch graph");
  node_t *H1_end_device = create_graph_node(topo, "H1_end_device");
  node_t *H2_end_device = create_graph_node(topo, "H2_end_device");
  node_t *H3_end_device = create_graph_node(topo, "H3_end_device");
  node_t *H4_end_device = create_graph_node(topo, "H4_end_device");
  node_t *node_sw = create_graph_node(topo, "node_sw");

  insert_link(H1_end_device, node_sw, "eth1/0", "eth5/1", 1);
  insert_link(H2_end_device, node_sw, "eth2/0", "eth5/2", 1);
  insert_link(H3_end_device, node_sw, "eth3/0", "eth5/3", 1);
  insert_link(H4_end_device, node_sw, "eth4/0", "eth5/4", 1);

  node_set_loopback_address(H1_end_device, "122.1.1.0");
  node_set_intf_ip_address(H1_end_device, "eth1/0", "20.1.1.1", 24);

  node_set_loopback_address(H2_end_device, "123.1.1.0");
  node_set_intf_ip_address(H2_end_device, "eth2/0", "20.2.1.1", 24);

  
  node_set_loopback_address(H3_end_device, "124.1.1.0");
  node_set_intf_ip_address(H3_end_device, "eth3/0", "20.3.1.1", 24);

  node_set_loopback_address(H4_end_device, "125.1.1.0");
  node_set_intf_ip_address(H4_end_device, "eth4/0", "20.4.1.1", 24);
 

  node_intf_set_l2_mode(node_sw, "eth5/1", ACCESS);
  node_intf_set_vlanid(node_sw, "eth5/1", 10);
  node_intf_set_l2_mode(node_sw, "eth5/2", ACCESS);
    node_intf_set_vlanid(node_sw, "eth5/2", 10);
  node_intf_set_l2_mode(node_sw, "eth5/3", ACCESS);
    node_intf_set_vlanid(node_sw, "eth5/3", 10);
  node_intf_set_l2_mode(node_sw, "eth5/4", ACCESS);
    node_intf_set_vlanid(node_sw, "eth5/4", 10);

  start_pkt_receiver_thread(topo);
  return topo;
}

ctrl_table_t *build_first_topo(){
  ctrl_table_t *topo = create_new_graph("first graph");
  node_t *R0_re = create_graph_node(topo, "R0_re");
  node_t *R1_re = create_graph_node(topo, "R1_re");
  node_t *R2_re = create_graph_node(topo, "R2_re");
  node_t *R3_re = create_graph_node(topo, "R3_re");



  insert_link(R0_re, R1_re, "eth0/0", "eth0/1", 1);
  insert_link(R1_re, R2_re, "eth0/2", "eth0/3", 1);
  insert_link(R2_re, R0_re, "eth0/5", "eth0/4", 1);
  insert_link(R2_re, R3_re, "eth0/6", "eth0/7", 1);

  node_set_loopback_address(R0_re, "122.1.1.0");
  node_set_intf_ip_address(R0_re, "eth0/0", "20.1.1.1", 24);
  node_set_intf_ip_address(R0_re, "eth0/4", "40.1.1.1", 24);


  node_set_loopback_address(R1_re, "122.1.1.1");
  node_set_intf_ip_address(R1_re, "eth0/1", "20.1.1.2", 24);
  node_set_intf_ip_address(R1_re, "eth0/2", "30.1.1.1", 24);

  node_set_loopback_address(R2_re, "122.1.1.2");
  node_set_intf_ip_address(R2_re, "eth0/3", "30.1.1.2", 24);
  node_set_intf_ip_address(R2_re, "eth0/5", "40.1.1.2", 24);
  node_set_intf_ip_address(R2_re, "eth0/6", "40.1.1.3", 24);

  node_set_loopback_address(R3_re, "123.1.1.2");
  node_set_intf_ip_address(R3_re, "eth0/7", "31.1.1.2", 24);

  
  start_pkt_receiver_thread(topo);
  return topo;

}
