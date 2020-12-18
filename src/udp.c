#include "udp.h"
#include "ip.h"
#include "icmp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * @brief udp处理程序表
 * 
 */
static udp_entry_t udp_table[UDP_MAX_HANDLER];

/**
 * @brief udp伪校验和计算
 *        1. 你首先调用buf_add_header()添加UDP伪头部
 *        2. 将IP头部拷贝出来，暂存被UDP伪头部覆盖的IP头部
 *        3. 填写UDP伪头部的12字节字段
 *        4. 计算UDP校验和，注意：UDP校验和覆盖了UDP头部、UDP数据和UDP伪头部
 *        5. 再将暂存的IP头部拷贝回来
 *        6. 调用buf_remove_header()函数去掉UDP伪头部
 *        7. 返回计算后的校验和。  
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dest_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dest_ip)
{
    // TODO
    udp_hdr_t* udp_head = (udp_hdr_t*)buf->data;
    uint16_t udp_len = swap16(udp_head->total_len);
    buf_add_header(buf, 12);
    uint8_t old_ip_head[12] = {};
    for(int i=0; i<12; i++){
        old_ip_head[i] = buf->data[i];
    }

    for(int i=0; i<NET_IP_LEN; i++){
        buf->data[i] = src_ip[i];
    }
    for(int i=0; i<NET_IP_LEN; i++){
        buf->data[i+NET_IP_LEN] = dest_ip[i];
    }
    buf->data[8] = 0;
    buf->data[9] = NET_PROTOCOL_UDP;
    uint16_t* udp_len_p = (uint16_t*)&buf->data[10];
    *udp_len_p = swap16(udp_len);
    if(buf->len%2 == 1){    // 长度为奇数
        buf_t temp_buf;     // 新建一个temp_buf, 其内容就是buf中的内容再加上尾部多出1字节的0
        memset(temp_buf.payload, 0, sizeof(temp_buf.payload));
        buf_init(&temp_buf, buf->len+1);
        memcpy(temp_buf.data, buf->data, buf->len);
        uint16_t real_checksum = checksum16((uint16_t*)temp_buf.data,temp_buf.len);
        for(int i=0; i<12; i++){
            buf->data[i] = old_ip_head[i];
        }
        buf_remove_header(buf, 12);
        return real_checksum;
    }else{
        uint16_t real_checksum = checksum16((uint16_t*)buf->data,buf->len);
        for(int i=0; i<12; i++){
            buf->data[i] = old_ip_head[i];
        }
        buf_remove_header(buf, 12);
        return real_checksum;
    }
}

/**
 * @brief 处理一个收到的udp数据包
 *        你首先需要检查UDP报头长度
 *        接着计算checksum，步骤如下：
 *          （1）先将UDP首部的checksum缓存起来
 *          （2）再将UDP首都的checksum字段清零
 *          （3）调用udp_checksum()计算UDP校验和
 *          （4）比较计算后的校验和与之前缓存的checksum进行比较，如不相等，则不处理该数据报。
 *       然后，根据该数据报目的端口号查找udp_table，查看是否有对应的处理函数（回调函数）
 *       
 *       如果没有找到，则调用buf_add_header()函数增加IP数据报头部(想一想，此处为什么要增加IP头部？？)
 *       然后调用icmp_unreachable()函数发送一个端口不可达的ICMP差错报文。
 * 
 *       如果能找到，则去掉UDP报头，调用处理函数（回调函数）来做相应处理。
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // printf("udp_in执行\n");
    // TODO
    udp_hdr_t* udp_head = (udp_hdr_t*)buf->data;
    if(udp_head->total_len < 8){
        printf("udp报头长度错误\n");
        return;
    }
    
    uint16_t old_checksum = swap16(udp_head->checksum);
    udp_head->checksum = 0;
    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    uint16_t new_checksum = udp_checksum(buf, src_ip, my_ip_addr);
    if(old_checksum != new_checksum){
        printf("udp checksum错误, old_checksum: %x, new_checksum: %x\n", old_checksum, new_checksum);
        return;
    }

    for(int i=0; i<UDP_MAX_HANDLER; i++){
        if(udp_table[i].valid == 1 && udp_table[i].port == swap16(udp_head->dest_port)){
            uint16_t src_port = swap16(udp_head->src_port);
            buf_remove_header(buf,sizeof(udp_hdr_t));
            udp_table[i].handler(&udp_table[i], src_ip, src_port, buf);
            return;
        }
    }
    printf("发送unreachable\n");
    buf_add_header(buf,sizeof(ip_hdr_t));
    icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要调用buf_add_header()函数增加UDP头部长度空间
 *        填充UDP首部字段
 *        调用udp_checksum()函数计算UDP校验和
 *        将封装的UDP数据报发送到IP层。    
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dest_ip 目的ip地址
 * @param dest_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dest_ip, uint16_t dest_port)
{
    // TODO
    // printf("udp_out执行, 将要发送给%d端口\n",dest_port);
    buf_add_header(buf,sizeof(udp_hdr_t));
    udp_hdr_t* udp_head = (udp_hdr_t*)buf->data;
    udp_head->src_port = swap16(src_port);
    udp_head->dest_port = swap16(dest_port);
    udp_head->total_len = swap16(buf->len);
    udp_head->checksum = 0;
    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    uint16_t real_checksum = udp_checksum(buf,my_ip_addr,dest_ip);
    udp_head->checksum = swap16(real_checksum);
    ip_out(buf, dest_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++)
        udp_table[i].valid = 0;
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++) //试图更新
        if (udp_table[i].port == port)
        {
            udp_table[i].handler = handler;
            udp_table[i].valid = 1;
            return 0;
        }

    for (int i = 0; i < UDP_MAX_HANDLER; i++) //试图插入
        if (udp_table[i].valid == 0)
        {
            udp_table[i].handler = handler;
            udp_table[i].port = port;
            udp_table[i].valid = 1;
            return 0;
        }
    return -1;
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    for (int i = 0; i < UDP_MAX_HANDLER; i++)
        if (udp_table[i].port == port)
            udp_table[i].valid = 0;
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dest_ip 目的ip地址
 * @param dest_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dest_ip, uint16_t dest_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dest_ip, dest_port);
}