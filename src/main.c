#include <stdio.h>
#include <string.h>
#include <time.h>
#include "net.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "time.h"
void handler(udp_entry_t *entry, uint8_t *src_ip, uint16_t src_port, buf_t *buf)
{
    printf("recv udp packet from %s:%d len=%d\n", iptos(src_ip), src_port, buf->len);
    for (int i = 0; i < buf->len; i++)
        putchar(buf->data[i]);
    putchar('\n');
    uint16_t len = 1800;
    //uint16_t len = 1000;
    uint8_t data[len];

    uint16_t dest_port = 60001;
    for (int i = 0; i < len; i++)
        data[i] = i;
    udp_send(data, len, 60000, src_ip, dest_port); //发送udp包
}

void tcp_handler(tcp_establish_socket_entry_t *entry, buf_t *buf)
{
    printf("Hello World\n");
}

int main(int argc, char const *argv[])
{
    clock_t start,now;
    int ping_count = 0; // 记录已发送的ping数量
    uint8_t dst_ip[NET_IP_LEN] = {192, 168, 133, 131};
    start = now = clock();

    net_init();               //初始化协议栈
    udp_open(60000, handler); //注册端口的udp监听回调
    //tcp_open(6666, tcp_handler);
    while (1)
    {   
        now = clock();
        if(ping_count < PING_LIST_SIZE && (now - start)/CLOCKS_PER_SEC >= 1){
            start = now;
            icmp_ping(dst_ip);
            ping_count++;
        }
        net_poll(); //一次主循环
        icmp_ping_refresh();
    }

    return 0;
}
