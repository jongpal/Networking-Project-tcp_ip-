#ifndef __COMM__
#define __COMM__
#include "graph.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#define MAX_PKT_BUF_SIZE 512

typedef struct th_arg_list {
  node_t* node;
  int no;
  pthread_t *tid;
}th_arg_list;

// void start_fd_handler_thread(th_arg_list * tal);
void start_fd_handler_thread(node_t *entry);
unsigned int gen_udp_port_no();
void config_node_udp_props(node_t* node);
void init_udp_socket(node_t* node, fd_set *backup_fds, int *max_fd);
// void init_udp_socket(node_t* node);
// static void* handle_recv(void* arg_list);
static void* handle_recv(void* arg);
static void* init_pkt_receiver(void* topo);
static int pkt_recv(node_t *node, char* intf_name, char *data, unsigned int data_size);
// static void* handle_recv(void* arg_list);
// void start_fd_handler_thread(th_arg_list* tal);
void start_pkt_receiver_thread(ctrl_table_t *topo);
int send_pkt(char *pkt, unsigned int pkt_size, interface_t *interface);
int send_pkt_flood(node_t *node, interface_t *exempted_intf, char *pkt, unsigned int pkt_size);
void config_nw_addr(struct sockaddr_in *addr, char *ip_addr,uint32_t port_no, int ip_protocol_no, char mode);
void pkt_shift_toleft(char *pkt, unsigned int pkt_size, int shift_size);
#endif