#include "ethernet.h"

#include "arp.h"
#include "buf.h"
#include "driver.h"
#include "ip.h"
#include "net.h"
#include "utils.h"
#include <stdint.h>
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    if(buf->len < sizeof(ether_hdr_t)) return;  // 数据包不完整,直接丢弃

    // 先获取src和protocol
    uint16_t *protocolptr = (uint16_t*) (buf->data + 12);
    uint16_t  protocol    = swap16(*protocolptr);  // 要从大端变成小端
    uint8_t  *mac         = (uint8_t*) (buf->data + 6);

    // 调用buf_remove_header移除包头
    buf_remove_header(buf, sizeof(ether_hdr_t));

    // 调用net_in向上层传递数据包
    net_in(buf, protocol, mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // 判断是否需要进行填充
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }

    // 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // 目的MAC地址、源MAC以及协议类型protocol
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);  // 发送出去要从小端转换成大端

    driver_send(buf);  // send eth
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
