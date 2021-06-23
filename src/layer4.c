#include "../include/layer4.h"
#include "../include/tcpconst.h"
#include "../include/layer3.h"
#include <assert.h>
// #include <stdint.h>

extern void demote_pkt_to_l3(node_t *node, char *data, unsigned int data_size, int protocol_number, unsigned int dest_ip);
extern void process_ip_registration_request(node_t *node, char **payload, unsigned int *payload_size,interface_t *recv_intf, uint32_t *dest_ip, char *is_home_agent);
extern void process_ip_register_reply_request(node_t *node, char *payload, interface_t *recv_intf, uint32_t *dest_ip);

// static void mk_ip_registration_request_pkt_from_ip_pkt(node_t *node, interface_t *recv_intf, unsigned int dest_ip, char *payload, unsigned int *payload_size);
static void l4_append_udp_hdr(char *payload, unsigned int src_port, unsigned int dest_port, unsigned int* payload_size);

static void listening_process(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, unsigned int process_port_num){
  switch(process_port_num){
    case UDP_PORT_NUM_RESERVED_FOR_MOBILE_IP_REG_REQ: {
      udp_hdr_t *udp_hdr = (udp_hdr_t *)payload;
      char *udp_payload = CHAR_UDP_HDR_PTR_TO_PAYLOAD(udp_hdr);

      uint32_t dest_ip;
      char is_home_agent = 0;
      process_ip_registration_request(node, &udp_payload, &payload_size,recv_intf, &dest_ip, &is_home_agent);
      payload_size -= sizeof(udp_hdr_t);
      udp_payload -= sizeof(udp_hdr_t);
      if(is_home_agent)
        l4_append_udp_hdr(udp_payload, udp_hdr->dest_port, udp_hdr->src_port, &payload_size);
      else {
        l4_append_udp_hdr(udp_payload, udp_hdr->src_port, udp_hdr->dest_port, &payload_size);
      }
      char *pp = CHAR_UDP_HDR_PTR_TO_PAYLOAD((udp_hdr_t *)udp_hdr);
      demote_pkt_to_l3(node, udp_payload, payload_size, UDP, dest_ip); 
      //src port => dest port (reverse it) 
    }
    default: break;
  }
}


static void l4_process_udp_from_btm(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size){
  
  udp_hdr_t *udp_hdr = (udp_hdr_t *)payload;
  char *udp_payload = CHAR_UDP_HDR_PTR_TO_PAYLOAD(udp_hdr);
  // char *udp_payload = (char*)udp_hdr + sizeof(udp_hdr_t);
  switch(*udp_payload){
    case MOBILE_IP_REGISTRATION_REQUEST: {
      //printf("port %d\n", udp_hdr->dest_port);
      assert(udp_hdr->dest_port == UDP_PORT_NUM_RESERVED_FOR_MOBILE_IP_REG_REQ);
      listening_process(node, recv_intf, payload, payload_size, udp_hdr->dest_port); 
      
      // home agent or foreign agent
      return;
    }
    case MOBILE_IP_REGISTRATION_REPLY : {
      uint32_t dest_ip;

      process_ip_register_reply_request(node, udp_payload, recv_intf, &dest_ip);
      udp_payload -= sizeof(udp_hdr_t);
      payload_size -= sizeof(udp_hdr_t);

      if(dest_ip == 0) {
        printf("successfully received \n");
        // mobile node, registration all over
        return;
      }
      l4_append_udp_hdr(udp_payload, udp_hdr->src_port, udp_hdr->dest_port, &payload_size);
      demote_pkt_to_l3(node, udp_payload, payload_size, UDP, dest_ip);
    }
  }
}

static void l4_process_ICMP_from_btm(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size){
  //*payload for message type
  switch(*payload){
    case MOBILE_IP_REGISTRATION_REQUEST : {
      mbl_ip_register_req_msg_t *reg_msg = (mbl_ip_register_req_msg_t *)payload;
      payload -= sizeof(udp_hdr_t);
      char testip[16];
      ip_addr_n_to_p(reg_msg->coa,testip);
      // printf("coa : %s\n", testip);
      l4_append_udp_hdr(payload, node->udp_port_no, UDP_PORT_NUM_RESERVED_FOR_MOBILE_IP_REG_REQ, &payload_size);
      demote_pkt_to_l3(node, payload, payload_size, UDP, reg_msg->coa);
      break;
    }
    default: break;
  }
};

void promote_pkt_to_l4(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type){

  switch(protocol_type) {
    case ICMP: {
      // registration message
      l4_process_ICMP_from_btm(node, recv_intf, payload, payload_size);
      // dest ip : foreign agent
      return;
    }
    case UDP : {
      
      l4_process_udp_from_btm(node, recv_intf, payload, payload_size);
      return;
    }
    default : return;
  }  
};

static void l4_append_udp_hdr(char *payload, unsigned int src_port, unsigned int dest_port, unsigned int *payload_size){
  udp_hdr_t* udp_hdr = (udp_hdr_t *)payload;
  udp_hdr->src_port = src_port;
  udp_hdr->dest_port = dest_port;
  udp_hdr->checksum = 0;
  udp_hdr->tot_len = *payload_size + sizeof(udp_hdr_t);
  // payload -= sizeof(udp_hdr_t);
  *payload_size = udp_hdr->tot_len;
}




