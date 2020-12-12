#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{
    // TODO
    uint8_t my_ip_addr[8] = DRIVER_IF_IP;
    time_t now_time;
    time(&now_time);
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        arp_entry_t* arp_entry = &arp_table[i];
        if((now_time - arp_entry->timeout) > ARP_TIMEOUT_SEC){
            arp_entry->state = ARP_INVALID;
        }
        int j;      // 判断一下该ip是否是本机ip, 如果是则标记为INVALID
        for(j = 0; j < NET_IP_LEN; j++){
            if(arp_entry->ip[j] != my_ip_addr[j]){
                break;
            }
        }
        if(j == NET_IP_LEN){
            arp_entry->state = ARP_INVALID;
        }
    }

    // 查看该ip是否已存在, 若结果不为-1, 则代表存在于下标already_i的arp
    int already_i = -1; 
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        arp_entry_t* arp_entry = &arp_table[i];
        int j;
        for(j = 0; j < NET_IP_LEN; j++){
            if(arp_entry->ip[j] != ip[j]){
                break;
            }
        }
        if(j == NET_IP_LEN){
            already_i = i;
        }
    }

    if(already_i != -1){
        arp_entry_t* arp_entry = &arp_table[already_i];
        for(int j = 0; j < NET_IP_LEN; j++){
            arp_entry->ip[j] = ip[j];
        }
        for(int j = 0; j < NET_MAC_LEN; j++){
            arp_entry->mac[j] = mac[j];
        }
        arp_entry->state = state;
        arp_entry->timeout = now_time;
        return;
    }

    // 查找arp表中是否有INVALID
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        arp_entry_t* arp_entry = &arp_table[i];
        if(arp_entry->state == ARP_INVALID){
            for(int j = 0; j < NET_IP_LEN; j++){
                arp_entry->ip[j] = ip[j];
            }
            for(int j = 0; j < NET_MAC_LEN; j++){
                arp_entry->mac[j] = mac[j];
            }
            arp_entry->state = state;
            arp_entry->timeout = now_time;
            return;
        }
    }

    // arp表中没有INVALID, 需要找一个间隔时间最大的作为插入项
    int max_i = 0;
    time_t max_interval = 0;
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        arp_entry_t* arp_entry = &arp_table[i];
        if(now_time - arp_entry->timeout > max_interval){
            max_i = i;
            max_interval = now_time - arp_entry->timeout;
        }
    }
    
    arp_entry_t* arp_entry = &arp_table[max_i];
    for(int j = 0; j < NET_IP_LEN; j++){
        arp_entry->ip[j] = ip[j];
    }
    for(int j = 0; j < NET_MAC_LEN; j++){
        arp_entry->mac[j] = mac[j];
    }
    arp_entry->state = state;
    arp_entry->timeout = now_time;
    return;
}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
static void arp_req(uint8_t *target_ip)
{
    // TODO
    buf_init(&txbuf,sizeof(arp_pkt_t));
    arp_pkt_t* p = (arp_pkt_t*)txbuf.data;
    p->hw_type = swap16(0x1);
    p->pro_type = swap16(0x0800);
    p->hw_len = 0x6;
    p->pro_len = 0x4;
    p->opcode = swap16(ARP_REQUEST);
    uint8_t my_mac_addr[NET_MAC_LEN] = DRIVER_IF_MAC;
    for(int i=0; i < NET_MAC_LEN; i++){
        p->sender_mac[i] = my_mac_addr[i];
    }
    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    for(int i=0; i < NET_IP_LEN; i++){
        p->sender_ip[i] = my_ip_addr[i];
    }
    
    for(int i=0; i < NET_IP_LEN; i++){
        p->target_ip[i] = target_ip[i];
    }

    for(int i=0; i < NET_MAC_LEN; i++){
        p->target_mac[i] = 0x00;
    }
    uint8_t target_mac_addr[NET_MAC_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    arp_update(target_ip, target_mac_addr, ARP_PENDING);
    ethernet_out(&txbuf, target_mac_addr, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)
{
    // TODO
    // 首先进行报头检查
    arp_pkt_t* p = (arp_pkt_t*)buf->data;
    int opcode = swap16(p->opcode);
    if(p->hw_type != swap16(ARP_HW_ETHER)
        || p->pro_type != swap16(NET_PROTOCOL_IP)
        || p->hw_len != NET_MAC_LEN
        || p->pro_len != NET_IP_LEN
        || (opcode != ARP_REQUEST && opcode != ARP_REPLY)
    )
        return;
    
    arp_update(p->sender_ip, p->sender_mac, ARP_VALID);

    if(arp_buf.valid == 1){
        arp_out(&arp_buf.buf,arp_buf.ip,arp_buf.protocol);
        arp_buf.valid = 0;
    }else{
        if(swap16(p->opcode) == ARP_REQUEST){
            uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
            int i;
            for(i = 0; i < NET_IP_LEN; i++){
                if(p->target_ip[i] != my_ip_addr[i]){
                    break;
                }
            }
            if(i == NET_IP_LEN){    //发送应答报文
                buf_init(&txbuf, sizeof(arp_pkt_t));
                arp_pkt_t* reply_arp = (arp_pkt_t*)txbuf.data;
                reply_arp->hw_type = swap16(0x1);
                reply_arp->pro_type = swap16(0x0800);
                reply_arp->hw_len = 0x6;
                reply_arp->pro_len = 0x4;
                reply_arp->opcode = swap16(ARP_REPLY);
                uint8_t my_mac_addr[NET_MAC_LEN] = DRIVER_IF_MAC;
                for(int i=0; i < NET_MAC_LEN; i++){
                    reply_arp->sender_mac[i] = my_mac_addr[i];
                }
                uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
                for(int i=0; i < NET_IP_LEN; i++){
                    reply_arp->sender_ip[i] = my_ip_addr[i];
                }
                
                for(int i=0; i < NET_IP_LEN; i++){
                    reply_arp->target_ip[i] = p->sender_ip[i];
                }

                for(int i=0; i < NET_MAC_LEN; i++){
                    reply_arp->target_mac[i] = p->sender_mac[i];
                }
                
                ethernet_out(&txbuf, p->sender_mac, NET_PROTOCOL_ARP);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO
    int i,j;
    for(i=0; i < ARP_MAX_ENTRY; i++){
        for(j=0; j < NET_IP_LEN; j++){
            if(arp_table[i].ip[j] != ip[j]){
                break;
            }
        }
        if(j == NET_IP_LEN && arp_table[i].state == ARP_VALID){
            break;
        }
    }
    if(i == ARP_MAX_ENTRY){ //没找到arp
        arp_buf.buf = *buf;
        arp_buf.valid = 1;
        for(int k = 0; k < NET_IP_LEN; k++){
            arp_buf.ip[k] = ip[k];
        }
        arp_buf.protocol = protocol;
        arp_req(ip);
    }else{
        ethernet_out(buf, arp_table[i].mac, protocol);
    }

}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;
    arp_req(net_if_ip);
}