#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TODO
    // printf("ethernet_in执行\n");
    // printf("收到的数据为:\n");
    // for(int i=0; i<buf->len; i++){
    //     printf("%x ",buf->data[i]);
    // }
    // printf("\n");
    uint16_t protocol = ((uint16_t)(buf->data[2*NET_MAC_LEN] & 0xff) << 8) | buf->data[2*NET_MAC_LEN + 1];
    
    if(protocol == NET_PROTOCOL_IP){
        // printf("eth中长度:%d\n",buf->len);
        buf_remove_header(buf,sizeof(struct ether_hdr));
        ip_in(buf);
    }else if(protocol == NET_PROTOCOL_ARP){
        buf_remove_header(buf,sizeof(struct ether_hdr));
        arp_in(buf);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标ip地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TODO
    uint8_t self_mac[NET_MAC_LEN] = DRIVER_IF_MAC;
    buf_add_header(buf,sizeof(struct ether_hdr));

    for(int i=0;i<NET_MAC_LEN;i++){
        buf->data[i] = mac[i];
    }
    for(int i=0;i<NET_MAC_LEN;i++){
        buf->data[i+NET_MAC_LEN] = self_mac[i];
    }
    buf->data[2*NET_MAC_LEN] = (uint8_t)((protocol>> 8) & 0xff);
    buf->data[2*NET_MAC_LEN + 1] = (uint8_t)(protocol & 0xff);
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
