#ifndef ICMP_H
#define ICMP_H
#include <stdint.h>
#include "utils.h"
#include "time.h"
#pragma pack(1)
typedef struct icmp_hdr
{
    uint8_t type;      // 类型
    uint8_t code;      // 代码
    uint16_t checksum; // ICMP报文的校验和
    uint16_t id;       // 标识符
    uint16_t seq;      // 序号
} icmp_hdr_t;

#pragma pack()
typedef enum icmp_type
{
    ICMP_TYPE_ECHO_REQUEST = 8, // 回显请求
    ICMP_TYPE_ECHO_REPLY = 0,   // 回显响应
    ICMP_TYPE_UNREACH = 3,      // 目的不可达
} icmp_type_t;

typedef enum icmp_code
{
    ICMP_CODE_PROTOCOL_UNREACH = 2, // 协议不可达
    ICMP_CODE_PORT_UNREACH = 3      // 端口不可达
} icmp_code_t;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip, uint8_t ttl);

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code);

#define PING_LIST_SIZE 5
typedef struct ping_entry
{
    int valid;          // 代表该条记录是否有效
    clock_t timestamp;  // 时间戳
    uint16_t icmp_seq;  // icmp报文的序列号
} ping_entry_t;


void icmp_ping(uint8_t *dst_ip);
void icmp_init();
void icmp_ping_refresh();
#endif
