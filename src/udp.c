#include "udp.h"

#include "buf.h"
#include "icmp.h"
#include "ip.h"
#include "map.h"
#include "net.h"
#include "utils.h"
#include <stdint.h>

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // 包检查
    // 是否小于UDP首部长度
    if(buf->len < sizeof(udp_hdr_t)) return;
    // 是否小于首部字段给出的长度
    udp_hdr_t* udp_hdr = (udp_hdr_t*)buf->data;
    if(buf->len < swap16(udp_hdr->total_len16)) return;

    // 重新计算校验和
    uint16_t checksum16_origin = udp_hdr->checksum16;
    udp_hdr->checksum16 = 0;
    // 目的IP就是本机IP,因为是我们收到的这个udp数据包
    uint16_t checksum16_current = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    if(checksum16_origin != checksum16_current) return;
    udp_hdr->checksum16 = checksum16_current;

    // 查询处理函数
    uint16_t dst_port = swap16(udp_hdr->dst_port16);
    udp_handler_t* udp_handler = map_get(&udp_table, &dst_port);

    // 如果没有找到对应的处理函数
    if(udp_handler == NULL) {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return;
    }

    // 调用处理函数
    buf_remove_header(buf, sizeof(udp_hdr_t));
    (*udp_handler)(buf->data, buf->len, src_ip, swap16(udp_hdr->src_port16));
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // 添加UDP报头
    buf_add_header(buf, sizeof(udp_hdr_t));

    // 填充UDP首部
    udp_hdr_t* udp_hdr = (udp_hdr_t*)buf->data;
    udp_hdr->dst_port16 = swap16(dst_port);
    udp_hdr->src_port16 = swap16(src_port);
    udp_hdr->checksum16 = 0;
    udp_hdr->total_len16 = swap16(buf->len);

    // 填写校验和
    udp_hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // 发送UDP数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}