/* UDP socket : Physical layer abstraction */

#include "../include/hash.h"
#include "../include/communication.h"
#include <signal.h>

// #include "graph.h"

#define NUM_RECV_BUF 5
#define NUM_SEND_BUF 5

static char recv_buffer[MAX_PKT_BUF_SIZE * NUM_RECV_BUF];
static char send_buffer[MAX_PKT_BUF_SIZE * NUM_SEND_BUF];
// static char send_buffer[MAX_PKT_BUF_SIZE];

pthread_mutex_t recvd_mut= PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t recvd_sig= PTHREAD_COND_INITIALIZER;

// pthread_mutex_t sent_mut= PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t sent_sig= PTHREAD_COND_INITIALIZER;
char is_recvd = 0;
// char is_sent = 0;

typedef enum ip_protocol { IPV4 = 0, IPV6 = 1} ip_t;

extern void l2_recv_frame(node_t *node, char *intf_name, char *data, unsigned int data_size);

char buf[NUM_RECV_BUF];
int recv_fill_ptr = 0;
int recv_use_ptr = 0;
int recv_count = NUM_RECV_BUF;

char buf_send[NUM_SEND_BUF];
int send_fill_ptr = 0;
int send_use_ptr = 0;
int send_count = NUM_SEND_BUF;


pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t fill = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mut_send = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t empty_send = PTHREAD_COND_INITIALIZER;
pthread_cond_t fill_send = PTHREAD_COND_INITIALIZER;
typedef enum send_recv_buf {
  RECV_BUF = 1,
  SEND_BUF = 2
} send_recv;

void put(send_recv t) {
  if(t == RECV_BUF){
    buf[recv_fill_ptr] = 1;
    recv_fill_ptr = (recv_fill_ptr + 1) % NUM_RECV_BUF;
    recv_count++;
  }else {
    buf_send[send_fill_ptr] = 1;
    send_fill_ptr = (send_fill_ptr + 1) % NUM_SEND_BUF;
    send_count++;
  }
}
char get(send_recv t) {
  if(t == RECV_BUF){
    int tmp = recv_use_ptr;
    recv_use_ptr = (recv_use_ptr + 1) % NUM_RECV_BUF;
    recv_count--;
    return tmp;
  } else {
    int tmp = send_use_ptr;
    send_use_ptr = (send_use_ptr + 1) % NUM_SEND_BUF;
    send_count--;
    return tmp;
  }
}

void producer(send_recv t) {
  int i;
  switch(t){
    case RECV_BUF: {
      pthread_mutex_lock(&mut);
      while(recv_count == NUM_RECV_BUF)
        pthread_cond_wait(&empty, &mut);
      put(t);
      pthread_cond_signal(&fill);
      pthread_mutex_unlock(&mut);
      break;
    }
    case SEND_BUF: {
      pthread_mutex_lock(&mut_send);
      while(send_count == NUM_RECV_BUF)
        pthread_cond_wait(&empty_send, &mut_send);
      put(t);
      pthread_cond_signal(&fill_send);
      pthread_mutex_unlock(&mut_send);
      break;
    }
  }
}

int consumer(send_recv t) {
  int i;
  switch(t){
    case RECV_BUF:{
      pthread_mutex_lock(&mut);
      while(recv_count == 0)
        pthread_cond_wait(&fill, &mut);
      int available_slot = get(t);
      pthread_cond_signal(&empty);
      pthread_mutex_unlock(&mut);
      return available_slot;

    }
    case SEND_BUF:{
      pthread_mutex_lock(&mut_send);
      while(send_count == 0)
        pthread_cond_wait(&fill_send, &mut_send);
      int available_slot = get(t);
      pthread_cond_signal(&empty_send);
      pthread_mutex_unlock(&mut_send);
      return available_slot;
    }
  }
}

unsigned int base_port = 4000;
unsigned int gen_udp_port_no(){
  return base_port++;
}

void config_node_udp_props(node_t* node){
  node->udp_port_no = gen_udp_port_no();
}

void pkt_clear_left_mem(char *pkt, unsigned int pkt_size, int shift_size){
  if(shift_size > IF_NAME_SIZE) {
    printf("error : no available memory \n");
    exit(1);
  }
  memset(pkt-shift_size, 0, shift_size);
};

void config_nw_addr(struct sockaddr_in *addr, char *ip_addr,unsigned int port_no, int ip_protocol_no, char mode){
  //mode 0 : general ip request mode 1: INADDR_ANY
  addr->sin_port = htons(port_no);
  addr->sin_family = ip_protocol_no == 0 ? AF_INET : AF_INET6;
  addr->sin_addr.s_addr = mode == 1 ? INADDR_ANY : inet_addr(ip_addr);
}

void init_udp_socket(node_t* node, fd_set *backup_fds, int *max_fd){
  if((node->udp_sock_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(stderr, "UDP socket file descriptor creation failed \n");
    exit(1);
  }
  struct sockaddr_in udp_addr;
  config_nw_addr(&udp_addr, NULL, node->udp_port_no, 0, 1);

  if(bind(node->udp_sock_fd, (struct sockaddr *)&udp_addr, sizeof(struct sockaddr)) == -1){
    fprintf(stderr, "binding file descriptor with node address failed\n");
    exit(1);
  };
  FD_SET(node->udp_sock_fd, backup_fds);
  if(node->udp_sock_fd >= *max_fd) 
    *max_fd = node->udp_sock_fd;
}


static void* init_pkt_receiver(void* topo) {
  fd_set backup_fds, active_fds;
  ctrl_table_t* graph = (ctrl_table_t *)topo;
  unsigned int addr_len = sizeof(struct sockaddr);
  struct timeval t = { 10, 0 };
  struct sockaddr_in sender_addr;
  int err, bytes_recvd, count_nodes;
  int max_fd = -1;

  FD_ZERO(&backup_fds);
  FD_ZERO(&active_fds);

  for(int i = 0 ; i < graph->table_size; i++) {
    if(!(graph->table_ptr[i].is_entry)) continue;
    init_udp_socket(graph->table_ptr[i].entry, &backup_fds, &max_fd);
  }
  
  while(1) {
    memcpy(&active_fds, &backup_fds, sizeof(fd_set));
    // select(max_fd + 1, &active_fds, 0, 0, &t);
    select(max_fd + 1, &active_fds, 0, 0, 0);
    for(int i = 0 ; i < graph->table_size; i++) {
      if(!(graph->table_ptr[i].is_entry)) continue;
      if(FD_ISSET(((node_t *)(graph->table_ptr[i].entry))->udp_sock_fd, &active_fds)) {
        // printf("one time : %s\n", ((node_t *)(graph->table_ptr[i].entry))->name);
        start_fd_handler_thread(graph->table_ptr[i].entry);
      }
    }
  }
}

static int pkt_recv(node_t *node, char* intf_name, char *data, unsigned int data_size) {
  printf("message received on node = %s, IIF = %s\n", node->name, intf_name);
  
  

  interface_t *intf = get_node_if_by_name(node, intf_name);
  if(IS_IF_UP(intf) == FALSE) {
    printf("interface %s disabled dropping the pkt \n", intf_name);
    return 0;
  }
  // increase rx_counter;
  intf->intf_nw_props.rx_counter ++;
  // 4 Bytes for possible vlan hdr
  pkt_clear_left_mem(data, data_size, 4);
  l2_recv_frame(node, intf->name, data, data_size);
  return 0;
}


static void* handle_recv(void* arg){

  node_t *node = (node_t *)arg;
  int bytes_recvd;
  int error;
  struct sockaddr_in sender_addr;
 
  unsigned int addr_len = sizeof(struct sockaddr);
  int available_slot = consumer(RECV_BUF);
  //printf("recv avialable slot  %d \n",available_slot);
  memset(recv_buffer+MAX_PKT_BUF_SIZE*available_slot, 0, MAX_PKT_BUF_SIZE);
  if((bytes_recvd = recvfrom(node->udp_sock_fd, recv_buffer+MAX_PKT_BUF_SIZE*available_slot, MAX_PKT_BUF_SIZE, 0, (struct sockaddr*)&sender_addr, &addr_len)) == -1) {
    fprintf(stderr, "receiving msg failed, errno :%d \n", errno);
    exit(1);
  };

  pthread_mutex_lock(&recvd_mut);
  is_recvd = 1;
  pthread_cond_signal(&recvd_sig);
  pthread_mutex_unlock(&recvd_mut);
  // 다시 init_pkt 함수에서 polling 할수있게
  pthread_detach(pthread_self());

  // the first part of packet wil be interface's name
  char *intf_name = recv_buffer+MAX_PKT_BUF_SIZE*available_slot;

  char *data = recv_buffer+MAX_PKT_BUF_SIZE*available_slot+strlen(intf_name)+1;
  pkt_recv(node, intf_name, data, bytes_recvd - strlen(intf_name)-1);
  // recvd_buffer 자원 해제
  producer(RECV_BUF);
  return NULL;
};

void start_fd_handler_thread(node_t *entry){
  pthread_attr_t attr;
  pthread_t tid;
  pthread_attr_init(&attr);
  pthread_create(&tid, &attr, handle_recv, (void *)entry);
  // wait before terminates : only after the thread recvd the msg

  pthread_mutex_lock(&recvd_mut);
  while(is_recvd != 1)
    pthread_cond_wait(&recvd_sig, &recvd_mut);
  is_recvd = 0;
  pthread_mutex_unlock(&recvd_mut);
}

void start_pkt_receiver_thread(ctrl_table_t *topo) {
  pthread_attr_t attr;
  pthread_t recv_pkt_thread_id;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if(pthread_create(&recv_pkt_thread_id, &attr, init_pkt_receiver, (void *)topo)){
    fprintf(stderr,"error creating thread\n");
  };
}


int send_pkt(char *pkt, unsigned int pkt_size, interface_t *interface){
  node_t *sender_node = interface->node;
  interface_t *nbr_node_intf = get_nbr_node_intf(interface);
  int sockfd;
  int bytes_sent;
  if(IS_IF_UP(interface) == FALSE) {
    printf("interface disabled.\n");
    return 0;
  }
  if(!nbr_node_intf) {
    fprintf(stderr, "no neighbor node for that interface : %s\n", interface->name);
    return -1;
  }
  struct sockaddr_in receiver;
  
  //increase tx counter
  interface->intf_nw_props.tx_counter++;
  //printf("port : %d, to %s\n", (nbr_node_intf->node->udp_port_no),nbr_node_intf->name);
  config_nw_addr(&receiver, "127.0.0.1", nbr_node_intf->node->udp_port_no, 0, 0);

  int available_slot = consumer(SEND_BUF);
  //printf("available send : %d\n", available_slot);
  char* send_buf = send_buffer + MAX_PKT_BUF_SIZE*available_slot;

  int name_size = strlen(nbr_node_intf->name);
  strncpy(send_buf, nbr_node_intf->name, name_size);
  send_buf[name_size] = '\0';

  // pkt_shift_toright(send_buffer+name_size+1, pkt, pkt_size, MAX_PKT_BUF_SIZE - (name_size+1));

  memcpy(send_buf+name_size+1, pkt, pkt_size);
  
  if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    fprintf(stderr, "UDP socket creation failed\n");
    return -1;
  }

  bytes_sent = sendto(sockfd, send_buf, pkt_size + name_size + 1, 0, (struct sockaddr*)&receiver, sizeof(struct sockaddr));

  //printf("i, send :%d\n", bytes_sent);
  
   memset(send_buf, 0, MAX_PKT_BUF_SIZE);
  producer(SEND_BUF);
  close(sockfd);
  return 1;
}

int send_pkt_flood(node_t *node, interface_t *exempted_intf, char *pkt, unsigned int pkt_size){

  int until = get_node_intf_available_slot(node);
  
  for(int i = 0; i < until; i++) {
    if(exempted_intf && (strncmp(node->if_list[i]->name, exempted_intf->name, IF_NAME_SIZE) == 0)) continue;
    send_pkt(pkt, pkt_size, node->if_list[i]);
  }
  return 1;
};


