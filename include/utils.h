#ifndef __UTIL__
#define __UTIL__
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define PREFIX_LEN 16
#define UNSET_BIT(i_mask, pos) i_mask = i_mask & ((1 << pos)^0xffffffff)

void put_uchar_mac_into_char(unsigned char* mac, char *charred_mac);

void layer2_fill_with_broadcast_mac(unsigned char *broad_mac_array);

void apply_mask(char *prefix, char mask, char *str_prefix);



#define IS_MAC_BROADCAST_ADDR(mac) (((mac[0]) & (mac[1]) & (mac[2]) & (mac[3]) & (mac[4]) & (mac[5])) == 0xff)
#endif