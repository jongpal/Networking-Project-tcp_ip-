#include "./../include/hash.h"
#include "./../CommandParser/libcli.h"
#include <unistd.h>
extern ctrl_table_t *build_first_topo();
extern ctrl_table_t *build_l2_switch_topo();
extern ctrl_table_t *mobile_ip_topo();
extern ctrl_table_t *build_dual_switch_topo();
extern ctrl_table_t *linear_3_node_topo();
extern ctrl_table_t *inter_vlan_topo();
extern ctrl_table_t *route_construction_test_topo();

extern void nw_init_cli();

ctrl_table_t *topo = NULL;

int main(int argc, char **argv) {
  nw_init_cli();  
 // topo = build_dual_switch_topo();
  //topo = linear_3_node_topo();
  //topo = inter_vlan_topo();
  topo = mobile_ip_topo();
  //topo = route_construction_test_topo();
  // dump_nw_graph(topo);
  sleep(2);

  start_shell();
  //sleep(10);
  free_nw_graph(topo);  
  return 0;
} 

