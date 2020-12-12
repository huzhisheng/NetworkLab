#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查ICMP报头长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */

void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TODO
    if(buf->len < sizeof(icmp_hdr_t)){
        return;
    }
    icmp_hdr_t* icmp_head = (icmp_hdr_t*)buf->data;
    if(icmp_head->type == 8 && icmp_head->code == 0){
        buf_init(&txbuf,buf->len);
        icmp_hdr_t* new_icmp = (icmp_hdr_t*)txbuf.data;
        new_icmp->type = 0;
        new_icmp->code = 0;
        new_icmp->checksum = 0;
        new_icmp->id = icmp_head->id;
        new_icmp->seq = icmp_head->seq;
        memcpy(&txbuf.data[sizeof(icmp_hdr_t)], &buf->data[sizeof(icmp_hdr_t)], buf->len - sizeof(icmp_hdr_t));
        uint16_t real_checksum = checksum16((uint16_t*)(txbuf.data), txbuf.len); // checksum覆盖的区域是整个ICMP头+ICMP数据?
        new_icmp->checksum = swap16(real_checksum);
        ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
    }
}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TODO
    buf_init(&txbuf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
    icmp_hdr_t* new_icmp = (icmp_hdr_t*)txbuf.data;
    new_icmp->type = 3;
    new_icmp->code = code;
    new_icmp->checksum = 0;
    new_icmp->id = 0;
    new_icmp->seq = 0;
    memcpy(&txbuf.data[sizeof(icmp_hdr_t)], recv_buf->data, sizeof(ip_hdr_t) + 8);
    uint16_t real_checksum = checksum16((uint16_t*)(txbuf.data), txbuf.len);
    new_icmp->checksum = swap16(real_checksum);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}