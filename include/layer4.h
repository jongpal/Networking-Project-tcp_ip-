#ifndef __LAYER4_H__
#define __LAYER4_H__
#include <stdint.h>
#include "communication.h"

#pragma pack(push, 1)
typedef struct udp_header {
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t tot_len;
  uint16_t checksum;
} udp_hdr_t;
#pragma pack(pop)

static char* CHAR_UDP_HDR_PTR_TO_PAYLOAD(udp_hdr_t *udp_hdr) {
  return ((char *)udp_hdr)+sizeof(udp_hdr_t);
} 

void promote_pkt_to_l4(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type);

#endif