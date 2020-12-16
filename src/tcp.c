#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define swap32(x) ((((x)&0xFF) << 24) | (((x)&0xFF00) << 8) | (((x)&0xFF0000) >> 8) | (((x)>>24) & 0xFF)) //为32位数据交换大小端
static tcp_listening_socket_entry_t tcp_listening_table[TCP_MAX_LISTENER];      // listening表
static tcp_establish_socket_entry_t tcp_establish_table[TCP_MAX_ESTABLISH];     // establish表

static uint16_t tcp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dest_ip)
{
    // TODO
    tcp_hdr_t* tcp_head = (tcp_hdr_t*)buf->data;
    uint16_t tcp_len = ((swap16(tcp_head->offset_and_flags) & 0xf000) >> 12) * 4;
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
    buf->data[9] = 6;
    uint16_t* tcp_len_p = (uint16_t*)&buf->data[10];
    *tcp_len_p = swap16(tcp_len);
    uint16_t real_checksum = checksum16((uint16_t*)buf->data,buf->len);
    for(int i=0; i<12; i++){
        buf->data[i] = old_ip_head[i];
    }
    buf_remove_header(buf, 12);
    return real_checksum;



}
void tcp_in(buf_t *buf, uint8_t *src_ip){
    for(int i=0; i<20; i++){
        printf("%x ",buf->data[i]);
    }
    printf("\n");
    tcp_hdr_t* tcp_head = (tcp_hdr_t*)buf->data;
    // 对TCP报头进行检查
    uint16_t offset_and_flags = swap16(tcp_head->offset_and_flags);
    uint8_t hdr_len = ((offset_and_flags >> 12) & 0xF)*4;
    uint16_t old_checksum = swap16(tcp_head->checksum);
    tcp_head->checksum = 0;
    uint8_t my_ip_addr[NET_IP_LEN] = DRIVER_IF_IP;
    uint16_t new_checksum = tcp_checksum(buf, src_ip, my_ip_addr);
    if(hdr_len < 20){
        printf("Error: TCP报文首部长度有误, %d\n",hdr_len);
        return;
    }
    if(old_checksum != new_checksum){
        printf("Error: TCP报文校验和有误, %x, %x\n", old_checksum, new_checksum);
        return;
    }
    // 先提取出各字段的值, 方便后续处理
    uint16_t src_port = swap16(tcp_head->src_port);
    uint16_t dst_port = swap16(tcp_head->dest_port);
    uint32_t seq_num = swap32(tcp_head->seq_num);
    uint32_t ack_num = swap32(tcp_head->ack_num);
    uint16_t win_len = swap16(tcp_head->win_len);
    uint8_t flag_ack = offset_and_flags & TCP_ACK;
    uint8_t flag_syn = offset_and_flags & TCP_SYN;
    uint8_t flag_fin = offset_and_flags & TCP_FIN;
    // 先在establish表中查找是否有对应的socket对该包进行处理
    // 否则发送port unreachable ICMP报文
    for(int i=0; i<TCP_MAX_ESTABLISH; i++){
        if(tcp_establish_table[i].valid == 1 && tcp_establish_table[i].lport == dst_port && tcp_establish_table[i].rport == src_port){
            int j;
            for(j=0; j<NET_IP_LEN; j++){
                if(src_ip[j] != tcp_establish_table[i].src_ip[j])
                    break;
            }
            if(j != NET_IP_LEN) 
                continue;
            else{   // 该包是在已建立的tcp连接中发送的包
                buf_remove_header(buf, hdr_len);
                if(!buf || buf->len == 0)
                    tcp_establish_table[i].ack_num += 1;
                else
                    tcp_establish_table[i].ack_num += buf->len;

                tcp_establish_table[i].win_len -= buf->len;

                if(flag_fin != 0){  // 对方请求中断连接, 我们也立即回复FIN, 即不需要4次挥手, 3次挥手即可
                    uint16_t offset_and_flags = make_offset_and_flags(sizeof(tcp_hdr_t), 1, 0, 1);
                    buf_init(&txbuf,0);
                    tcp_out(&tcp_establish_table[i], &txbuf, offset_and_flags);
                    tcp_establish_table[i].seq_num += 1;
                    tcp_establish_table[i].state == TCP_LAST_ACK;
                }else if(tcp_establish_table[i].state == TCP_LAST_ACK){ // 挥手完毕, 关闭该TCP连接
                    printf("Info: TCP连接关闭\n");
                    tcp_establish_table[i].state == TCP_CLOSED;
                    tcp_establish_table[i].valid = 0;
                }{  // 普通的数据包
                    printf("Info: 接收到数据包\n");
                    tcp_establish_table[i].handler(&tcp_establish_table[i], buf);
                }
                return;
            }
        }
    }

    // 再在listening表中查找是否有对应的socket对该包进行处理
    for(int i=0; i<TCP_MAX_LISTENER; i++){
        if(tcp_listening_table[i].valid == 1 && tcp_listening_table[i].lport == dst_port){  // 在本机中有服务器程序正在监听该端口
            // 首先在该监听端口的request_queue中查看是否已经有该连接请求
            tcp_request_socket_entry_t* request_p = tcp_listening_table[i].request_queue;
            tcp_request_socket_entry_t* request_last = 0;
            while(request_p){
                if(request_p->lport == dst_port && request_p->rport == src_port){
                    int j;
                    for(j=0; j<NET_IP_LEN; j++){
                        if(request_p->src_ip[j] != src_ip[j])
                            break;
                    }
                    if(j == NET_IP_LEN){    // 存在请求连接
                        if(flag_syn != 0 || flag_ack == 0){ // 重复的SYN包或ACK等于0的包, 需要重发第2次握手消息
                            printf("Info: 重复的SYN包或ACK等于0的包\n");
                            tcp_send_syn(&txbuf, src_ip, 1, seq_num+1, dst_port, src_port);
                            return;
                        }else{
                            // 是ACK包,说明需要将此request socket变为establish socket

                            // 将此request socket从队列中拿掉
                            if(request_last)
                                request_last->next = request_p->next;
                            else
                                tcp_listening_table[i].request_queue = request_p->next;
                            
                            if(insert_into_establish(request_p) < 0){   // 收到第3次握手, 将此TCP连接变为established状态
                                printf("Error: 建立established连接失败\n");
                            }
                            return;
                        }
                    }else{
                        request_last = request_p;
                        request_p = request_p->next;
                    }
                }
            }
            // 执行到这里说明, 该包是第一次发送到本机
            if(flag_syn == 0)   // 不建立连接就发送数据, 不讲武德
                return;
            
            tcp_request_socket_entry_t* new_request = (tcp_request_socket_entry_t*)malloc(sizeof(tcp_request_socket_entry_t));
            if(request_last)    // 将新创建的request socket插入到listening socket的接收队列中
                request_last->next = new_request;
            else
                tcp_listening_table[i].request_queue = new_request;
            
            new_request->ack_num = seq_num + 1;
            new_request->seq_num = TCP_SEQ_NUM_INIT;    // 后面这里应改为一个32位内的随机数
            new_request->lport = dst_port;
            new_request->rport = src_port;
            new_request->next = 0;
            new_request->handler = tcp_listening_table[i].handler;
            new_request->state = TCP_SYN_RECV;
            for(int j=0; j<NET_IP_LEN; j++){
                new_request->src_ip[j] = src_ip[j];
            }
            // 建立完request_socket后, 就需要回复给发送方第二次握手的消息
            tcp_send_syn(&txbuf, src_ip, 1, seq_num+1, dst_port, src_port);
        }
    }
}

int insert_into_establish(tcp_request_socket_entry_t* request_p){
    for (int i = 0; i < TCP_MAX_ESTABLISH; i++) //试图插入
        if (tcp_establish_table[i].valid == 0)
        {
            tcp_establish_table[i].handler = request_p->handler;
            tcp_establish_table[i].ack_num = request_p->ack_num;
            tcp_establish_table[i].lport = request_p->lport;
            tcp_establish_table[i].rport = request_p->rport;
            tcp_establish_table[i].seq_num = request_p->seq_num;
            for(int j=0; j<NET_IP_LEN; j++){
                tcp_establish_table[i].src_ip[j] = request_p->src_ip[j];
            }
            tcp_establish_table[i].state = TCP_ESTABLISHED;
            tcp_establish_table[i].win_len = TCP_WIN_LEN;
            tcp_establish_table[i].valid = 1;
            free(request_p);
            return 0;
        }
    return -1;
}

uint16_t make_offset_and_flags(uint16_t hdr_len, uint8_t flag_ack, uint8_t flag_syn, uint8_t flag_fin){
    uint16_t ret = (hdr_len/4) << 12;
    if(flag_ack != 0)
        ret |= TCP_ACK;
    if(flag_syn != 0)
        ret |= TCP_SYN;
    if(flag_fin != 0)
        ret |= TCP_FIN;
    return ret;
}

void tcp_out(tcp_establish_socket_entry_t *entry, buf_t *buf, uint16_t offset_and_flags)
{
    // TODO
    buf_add_header(buf,sizeof(tcp_hdr_t));
    tcp_hdr_t* tcp_head = (tcp_hdr_t*)buf->data;
    tcp_head->ack_num = swap32(entry->ack_num);
    tcp_head->seq_num = swap32(entry->seq_num);
    tcp_head->dest_port = swap16(entry->rport);
    tcp_head->src_port = swap16(entry->lport);
    tcp_head->offset_and_flags = swap16(offset_and_flags);
    tcp_head->win_len = swap16(entry->win_len);
    tcp_head->checksum = 0;
    tcp_head->urg_point = 0;
    tcp_head->checksum = swap16(checksum16((uint16_t*)buf->data, buf->len));
    ip_out(buf, entry->src_ip, NET_PROTOCOL_TCP);
}

/**
 * @brief 初始化tcp协议
 * 
 */
void tcp_init()
{
    for (int i = 0; i < TCP_MAX_LISTENER; i++){
        tcp_listening_table[i].valid = 0;
        tcp_listening_table[i].request_queue = 0;
    }
    
    for (int i = 0; i < TCP_MAX_ESTABLISH; i++)
        tcp_establish_table[i].valid = 0;
}

/**
 * @brief 打开一个tcp端口并注册处理程序
 * 
 * @param lport 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int tcp_open(uint16_t lport, tcp_handler_t handler)
{
    for (int i = 0; i < TCP_MAX_LISTENER; i++) //试图更新
        if (tcp_listening_table[i].lport == lport)
        {
            tcp_listening_table[i].handler = handler;
            tcp_listening_table[i].valid = 1;
            return 0;
        }

    for (int i = 0; i < TCP_MAX_LISTENER; i++) //试图插入
        if (tcp_listening_table[i].valid == 0)
        {
            tcp_listening_table[i].handler = handler;
            tcp_listening_table[i].lport = lport;
            tcp_listening_table[i].valid = 1;
            return 0;
        }
    return -1;
}

void tcp_send_syn(buf_t *buf, uint8_t* dst_ip, int ack_flag, uint32_t ack_num, uint16_t src_port, uint16_t dst_port){
    buf_init(&txbuf, 0);
    buf_add_header(&txbuf,sizeof(tcp_hdr_t) + 12);
    uint16_t offset_and_flags = make_offset_and_flags(sizeof(tcp_hdr_t) + 12, ack_flag, 1, 0);
    tcp_hdr_t* tcp_head = (tcp_hdr_t*)txbuf.data;
    tcp_head->ack_num = swap32(ack_num);
    tcp_head->seq_num = swap32(TCP_SEQ_NUM_INIT);
    tcp_head->dest_port = swap16(dst_port);
    tcp_head->src_port = swap16(src_port);
    tcp_head->offset_and_flags = swap16(offset_and_flags);
    tcp_head->win_len = TCP_WIN_LEN;
    tcp_head->checksum = 0;
    tcp_head->urg_point = 0;
    // 硬编码填写options字段
    uint8_t* tcp_options = &txbuf.data[sizeof(tcp_hdr_t)];
    tcp_options[0] = 2;
    tcp_options[1] = 4;
    uint16_t* tcp_mss = (uint16_t*)&tcp_options[2];
    *tcp_mss = swap16(0x05b4);  // mss=1460
    tcp_options[4] = 1;
    tcp_options[5] = 3;
    tcp_options[6] = 3;
    tcp_options[7] = 0;
    tcp_options[8] = 1;
    tcp_options[9] = 1;
    tcp_options[10] = 4;
    tcp_options[11] = 2;
    tcp_head->checksum = swap16(checksum16((uint16_t*)txbuf.data, txbuf.len));
    ip_out(&txbuf, dst_ip, NET_PROTOCOL_TCP);
    printf("Info: 握手消息已发送\n");
}