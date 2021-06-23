#ifndef __LAYER5_H__
#define __LAYER5_H__
#include "communication.h"

void ping(node_t *node, char *dest_ip);
void promote_pkt_to_l5(node_t *node, interface_t *recv_intf, char *payload, unsigned int payload_size, int protocol_type);

#endif