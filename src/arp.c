#include "arp.h"

#include "buf.h"
#include "ethernet.h"
#include "map.h"
#include "net.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // 调用init进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写ARP报头
    arp_pkt_t arp_packet = arp_init_pkt;
    arp_packet.opcode16 = swap16(ARP_REQUEST);
    memcpy(arp_packet.target_ip, target_ip, NET_IP_LEN);
    
    // 把报头填充到buf里面
    memcpy(txbuf.data, &arp_packet, sizeof(arp_pkt_t));

    // 发送APR报文
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // 调用init进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // 填写APR报头
    arp_pkt_t arp_packet = arp_init_pkt;
    arp_packet.opcode16 = swap16(ARP_REPLY);
    memcpy(arp_packet.target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_packet.target_mac, target_mac, NET_MAC_LEN);
     
    // 把报头填充到buf里面
    memcpy(txbuf.data, &arp_packet, sizeof(arp_pkt_t));
 
    // 发送APR报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // 检查数据报长度是否小于APR的头部长度
    if(buf->len < sizeof(arp_pkt_t)) return;

    // 检查报头数据
    arp_pkt_t *arp_pkt = (arp_pkt_t*) buf->data;
    
    if (arp_pkt->hw_type16 != swap16(ARP_HW_ETHER) ||
        arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        arp_pkt->hw_len != NET_MAC_LEN ||
        arp_pkt->pro_len != NET_IP_LEN ||
        (arp_pkt->opcode16 != swap16(ARP_REQUEST) &&
        arp_pkt->opcode16 != swap16(ARP_REPLY))
    ) return;

    // 更新ARP表项
    map_set(&arp_table, arp_pkt->sender_ip, src_mac);

    // 调用map_get获取arp_buf中的数据包
    buf_t *_arp_buf = (buf_t*)map_get(&arp_buf, arp_pkt->sender_ip);

    // 查看arp_buf中是否有对应的缓存
    if(_arp_buf != NULL) {
        // 有缓存就先处理该数据包,这个数据包是我们上次没找到MAC导致缓存下来的
        ethernet_out(_arp_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
        return;
    }
    else {
        // 判断是否是正确的请求报文
        if(arp_pkt->opcode16 == swap16(ARP_REQUEST) && !memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN)) {
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // 查找ARP表,根据IP地址查找MAC地址
    uint8_t *mac_address = (uint8_t *)map_get(&arp_table, ip);

    // 如果能找到MAC就直接发出去
    if(mac_address != NULL) {
        ethernet_out(buf, mac_address, NET_PROTOCOL_IP);  
    }
    else { // 没找到则需要进一步处理,需要判断buf此时是否有包(有就说明已经有arp请求了)
        if(map_get(&arp_buf, ip) == NULL) {
            // arp_buf存的是(ip, buf),指代的是这个buf应该发到哪个ip地址
            map_set(&arp_buf, ip, buf);  // map原始的键值对中值存的是数据包
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}