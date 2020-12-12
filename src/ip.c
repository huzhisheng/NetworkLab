#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
int ip_id = 0;   // 全局id

void ip_in(buf_t *buf)
{
    // TODO 
    // printf("ip_in中的长度为:%d\n", buf->len);
    ip_hdr_t* ip = (ip_hdr_t*)buf->data;
    if(ip->version != 0x4
        || swap16(ip->total_len) > 1500 
        || (ip->hdr_len)*4 > 60 
        || (ip->hdr_len)*4 < 20
    ){
        return;
    }

    uint16_t old_checksum = swap16(ip->hdr_checksum);
    ip->hdr_checksum = 0;
    uint16_t new_checksum = checksum16((uint16_t*)buf->data,sizeof(ip_hdr_t));   //IP的checksum只覆盖IP头
    ip->hdr_checksum = swap16(old_checksum);    //恢复checksum
    if(old_checksum != new_checksum)
        return;
    
    int i;
    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    for(i=0; i<NET_IP_LEN; i++){
        if(ip->dest_ip[i] != my_ip_addr[i])
            break;
    }
    if(i != NET_IP_LEN)
        return;
    uint8_t proto = ip->protocol;
    uint8_t src_ip[NET_IP_LEN];
    for(int i=0; i<NET_IP_LEN; i++){
        src_ip[i] = ip->src_ip[i];
    }
    
    switch (proto)
    {
        case NET_PROTOCOL_ICMP: //ICMP
            buf_remove_header(buf,sizeof(ip_hdr_t));
            icmp_in(buf, src_ip);
            break;
        case NET_PROTOCOL_UDP:    //UDP
            buf_remove_header(buf,sizeof(ip_hdr_t));
            udp_in(buf, src_ip);
            break;
        default:    //发送unreachable的icmp不需要去除ip头
            icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            break;
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TODO
    // id就是标识？
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t* ip_head = (ip_hdr_t*)buf->data;
    ip_head->hdr_len = sizeof(ip_hdr_t)/4;
    ip_head->version = 0x4;
    ip_head->tos = 0;
    ip_head->total_len = swap16(buf->len);
    ip_head->id = swap16(id);
    ip_head->flags_fragment = swap16(((id&0xffff) << 16) | ((mf & 0x1)<<13) | (offset/8));
    ip_head->ttl = 0x40;
    ip_head->protocol = protocol;
    ip_head->hdr_checksum = 0;

    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    for(int i=0; i<NET_IP_LEN; i++){
        ip_head->src_ip[i] = my_ip_addr[i];
    }
    for(int i=0; i<NET_IP_LEN; i++){
        ip_head->dest_ip[i] = ip[i];
    }
    uint16_t real_checksum = checksum16((uint16_t*)buf->data,sizeof(ip_hdr_t));
    ip_head->hdr_checksum = swap16(real_checksum);
    arp_out(buf,ip,NET_PROTOCOL_IP);
}

/**
 * @brief 处理一个要发送的ip数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - 以太网报头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - 以太网报头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：id为IP数据报的分片标识，从0开始编号，每增加一个分片，自加1。最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO 
    if(buf->len > 1500-sizeof(ip_hdr_t)){
        int left_data_len = buf->len;
        int offset = 0;
        while(left_data_len > 1500-sizeof(ip_hdr_t)){
            buf_t ip_buf;
            buf_init(&ip_buf, ETHERNET_MTU - sizeof(ip_hdr_t));
            memcpy(ip_buf.data, &buf->data[offset], 1500-sizeof(ip_hdr_t));
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, offset, 1);
            offset += 1500-sizeof(ip_hdr_t);
            left_data_len -= 1500-sizeof(ip_hdr_t);
        }
        buf_t ip_buf;
        buf_init(&ip_buf, left_data_len);
        memcpy(ip_buf.data, &buf->data[offset], left_data_len);
        ip_fragment_out(&ip_buf, ip, protocol, ip_id++, offset, 0);
    }else{
        ip_fragment_out(buf,ip,protocol,ip_id++,0,0);
    }
}
