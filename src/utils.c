#include "../include/utils.h"

void layer2_fill_with_broadcast_mac(unsigned char *broad_mac_array) {
  for(int i = 0 ; i < 6 ; i++){
    broad_mac_array[i] = 0xFF;
  }
}

void apply_mask(char *prefix, char mask, char *str_prefix){
  unsigned int i_mask = 0xffffffff;
  unsigned int bin_temp;
  inet_pton(AF_INET, prefix, &bin_temp);
  bin_temp = htonl(bin_temp);
  for(int i = 0 ; i < 32 - mask; i++)
    UNSET_BIT(i_mask, i);
  bin_temp = bin_temp & i_mask;
  bin_temp = htonl(bin_temp);
  inet_ntop(AF_INET, &bin_temp, str_prefix, PREFIX_LEN);
}

void put_uchar_mac_into_char(unsigned char* mac, char *charred_mac){
  snprintf(charred_mac, 13, "%x%x%x%x%x%x", mac[0],mac[1],mac[2], mac[3], mac[4], mac[5]);
  return;
};

