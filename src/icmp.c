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

static uint16_t ping_seq;
static uint16_t ping_id = 0x2468;


ping_entry_t icmp_ping_list[PING_LIST_SIZE];
// ping请求的统计信息
uint8_t ping_ip[NET_IP_LEN];
static int ping_count;  // ping报文有效数量
static int ping_get;    // ping报文回复的数量
static int ping_lost;   // ping报文丢失的数量
static int max_rtt = -1;            // 最大RTT时间
static int min_rtt = 0xffff;        // 最小RTT时间
static int total_rtt = 0;

void icmp_in(buf_t *buf, uint8_t *src_ip, uint8_t ttl)
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
    else if(icmp_head->type == 0 && icmp_head->code == 0 && swap16(icmp_head->id) == ping_id){  // ping应答
        for(int i=0; i<PING_LIST_SIZE; i++){
            if(icmp_ping_list[i].valid == 1 && icmp_ping_list[i].icmp_seq == swap16(icmp_head->seq)){   // 在ping_list表中查得到
                clock_t now = clock();
                int duration = (int)((now - icmp_ping_list[i].timestamp)/1000); // 经过的时间, 以毫秒为单位
                printf("来自%d.%d.%d.%d的回复：字节=%d 时间=%dms TTL=%d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], (int)(buf->len-sizeof(icmp_hdr_t)), duration, ttl);
                icmp_ping_list[i].valid = 0;
                // 更新ping请求的统计信息
                ping_count++;
                ping_get++;
                if(duration > max_rtt)max_rtt = duration;
                if(duration < min_rtt)min_rtt = duration;
                total_rtt += duration;
                if(ping_count == PING_LIST_SIZE){
                    ping_total_info();
                }
            }
        }
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

void icmp_ping(uint8_t *dst_ip){
    for(int i=0; i<NET_IP_LEN; i++){
        ping_ip[i] = dst_ip[i];
    }
    buf_init(&txbuf, sizeof(icmp_hdr_t) + 32);  // 填入61到77以及61到69两段数据(16进制)
    icmp_hdr_t* new_icmp = (icmp_hdr_t*)txbuf.data;
    new_icmp->type = 8;
    new_icmp->code = 0;
    new_icmp->checksum = 0;
    new_icmp->id = swap16(ping_id);
    new_icmp->seq = swap16(ping_seq);
    uint8_t* icmp_data = &txbuf.data[sizeof(icmp_hdr_t)];
    int i = 0;
    for(uint8_t d=0x61; d<=0x77; d++){
        icmp_data[i] = d;
        i++;
    }
    for(uint8_t d=0x61; d<=0x69; d++){
        icmp_data[i] = d;
        i++;
    }
    printf("正在 Ping %d.%d.%d.%d 具有%d字节数据:\n", dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3],(int)(txbuf.len-sizeof(icmp_hdr_t)));
    uint16_t real_checksum = checksum16((uint16_t*)(txbuf.data), txbuf.len);
    new_icmp->checksum = swap16(real_checksum);
    ip_out(&txbuf, dst_ip, NET_PROTOCOL_ICMP);

    // 将此条ping请求报文记录到ping表中
    icmp_ping_list[ping_seq].icmp_seq = ping_seq;
    icmp_ping_list[ping_seq].timestamp = clock();
    icmp_ping_list[ping_seq].valid = 1;
    ping_seq++;
}

void icmp_init(){
    for(int i=0; i<PING_LIST_SIZE; i++){
        icmp_ping_list[ping_seq].valid = 0;
    }
}

void icmp_ping_refresh(){
    clock_t now = clock();
    for(int i=0; i<PING_LIST_SIZE; i++){
        if(icmp_ping_list[i].valid && ((now - icmp_ping_list[i].timestamp)/CLOCKS_PER_SEC >= 2)){   // 该ping请求报文已经过期
            icmp_ping_list[i].valid = 0;
            printf("请求超时\n");
            // 更新ping请求的统计信息
            ping_count++;
            ping_lost++;
            if(ping_count == 5){
                ping_total_info();
            }
        }
    }
}

void ping_total_info(){ // ping执行完毕, 打印统计信息
    printf("\n");
    printf("%d.%d.%d.%d 的Ping统计信息:\n",ping_ip[0],ping_ip[1],ping_ip[2],ping_ip[3]);
    printf("\t数据包: 已发送=%d, 已接受=%d, 丢包率=%d%%\n",PING_LIST_SIZE,ping_get,ping_lost*100/PING_LIST_SIZE);
    if(ping_get > 0){
        printf("往返行程的估计时间:(以毫秒为单位)\n");
        printf("\t最短=%d, 最长=%d, 平均=%d\n", min_rtt, max_rtt, total_rtt/PING_LIST_SIZE);
    }
}

