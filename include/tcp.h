#ifndef TCP_H
#define TCP_H
#include <stdint.h>
#include "utils.h"
#pragma pack(1)
typedef struct tcp_hdr
{
    uint16_t src_port;  // 源端口
    uint16_t dest_port; // 目标端口
    uint32_t seq_num; 
    uint32_t ack_num;
    uint16_t offset_and_flags;  // 注意offset实际就是首部长度, 单位是4字节
    uint16_t win_len;
    uint16_t checksum;
    uint16_t urg_point;
} tcp_hdr_t;

#define TCP_OFFSET 0xf000

typedef enum tcp_flag   // 在offset_and_flags字段中方便进行与操作
{
    TCP_URG = 0x0020,
    TCP_ACK = 0x0010,
    TCP_PSH = 0x0008,
    TCP_RST = 0x0004,
    TCP_SYN = 0x0002,
    TCP_FIN = 0x0001,
} tcp_flag_t;

typedef enum tcp_state
{
    TCP_SYN_RECV = 0x20,
    TCP_ESTABLISHED = 0x10,
    TCP_CLOSE_WAIT = 0x08,
    TCP_LAST_ACK = 0x04,
    TCP_CLOSED = 0x02,
} tcp_state_t;

#define TCP_MAX_LISTENER 16
#define TCP_MAX_ESTABLISH 32
#define TCP_WIN_LEN 0x1234
#define TCP_SEQ_NUM_INIT 0x10000
typedef struct tcp_establish_socket_entry tcp_establish_socket_entry_t;
typedef struct tcp_request_socket_entry tcp_request_socket_entry_t;
typedef struct tcp_listening_socket_entry tcp_listening_socket_entry_t;

typedef void (*tcp_handler_t)(tcp_establish_socket_entry_t *entry, buf_t *buf);

struct tcp_listening_socket_entry
{
    int valid;              // 有效位
    int lport;              // local端口号
    tcp_handler_t handler;  // 处理程序
    tcp_request_socket_entry_t* request_queue;  // 接受队列
};

struct tcp_establish_socket_entry
{
    int valid;              // 有效位
    int lport;              // local端口号
    int rport;              // remote端口号
    uint8_t src_ip[NET_IP_LEN];  // 源IP
    uint8_t state;
    tcp_handler_t handler;  // 处理程序
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t win_len;   // 接收窗口大小
};

struct tcp_request_socket_entry
{
    struct tcp_request_socket_entry* next;
    int lport;              // local端口号
    int rport;              // remote端口号
    uint8_t src_ip[NET_IP_LEN];  // 源IP
    uint8_t state;
    tcp_handler_t handler;  // 处理程序
    uint32_t seq_num;
    uint32_t ack_num;
};

void tcp_in(buf_t *buf, uint8_t *src_ip);
int insert_into_establish(tcp_request_socket_entry_t* request_p);
uint16_t make_offset_and_flags(uint16_t hdr_len, uint8_t flag_ack, uint8_t flag_syn, uint8_t flag_fin);
void tcp_out(tcp_establish_socket_entry_t *entry, buf_t *buf, uint16_t offset_and_flags);
void tcp_init();
int tcp_open(uint16_t lport, tcp_handler_t handler);
#endif