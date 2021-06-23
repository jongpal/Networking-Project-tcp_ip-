#include "../include/layer5.h"
#include "../include/tcpconst.h"

extern void demote_pkt_to_l3(node_t *node, char *data, unsigned int data_size, int protocol_number, unsigned int dest_ip);
extern void mk_ping_echo_msg(node_t *host_node, char *payload, unsigned int *msg_size, char echo_msg_type);

static void process_ICMP_pkt(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size){
  // type
  switch(*payload) {
    case ICMP_ECHO_REPLY: {
      if(recv_intf == NULL) {
        printf("self ping : node %s, ip : %s", node->name, NODE_LO_ADDR(node));
        return;
      } else {
        printf("ping received => dest node %s, ip : %s,  \n", node->name, IF_IP(recv_intf));
        return;
        // free(payload);
      } 
    }
    default : {
      printf("undefined L5 behavior \n");
      return;
    }
  }
}

void promote_pkt_to_l5(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type){
  switch(protocol_type){
    case ICMP: {
      process_ICMP_pkt(node, recv_intf, payload, payload_size);
    }
    default: return;
  }
};

void ping(node_t *node, char *dest_ip){
  unsigned int uint32_ip;
  printf("src node : %s, ping ip : %s\n", node->name, dest_ip);
  // make enough room for other header could be added
  char *data = (char *)calloc(1, MAX_PKT_BUF_SIZE);
  unsigned int msg_size = 0;
  mk_ping_echo_msg(node, data, &msg_size, ICMP_ECHO_REQUEST);
  char some_data = 1; // additional payload , because in this simple ping function, we don't send actual data
  *(data + msg_size) = some_data;
  msg_size += sizeof(some_data);

  data += MAX_PKT_BUF_SIZE - msg_size;

  uint32_ip = ip_addr_p_to_n(dest_ip);
  
  demote_pkt_to_l3(node, data, msg_size, ICMP, uint32_ip);
}