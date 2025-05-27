#include "icmp.h"

#include "buf.h"
#include "ip.h"
#include "net.h"
#include "time.h"
#include "utils.h"
#include <stdint.h>
#include <string.h>

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // 初始化并封装数据,数据部分直接拷贝
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // 填写报头与校验和(标识符和序列号字段直接拷贝就行了)
    icmp_hdr_t* icmp_hdr = (icmp_hdr_t*)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;  // 类型换成响应报文
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t*)txbuf.data, txbuf.len);

    // 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // 报头检测
    if(buf->len < sizeof(icmp_hdr_t)) return;

    // 查看ICMP类型,如果是回显请求需要调用icmp_resp()进行应答
    icmp_hdr_t* icmp_hdr = (icmp_hdr_t*)buf->data;
    if(icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) icmp_resp(buf, src_ip);
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // 初始化并填写报头
    buf_init(&txbuf, sizeof(icmp_hdr_t)+sizeof(ip_hdr_t)+8);

    icmp_hdr_t* icmp_hdr = (icmp_hdr_t*)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    icmp_hdr->checksum16 = 0;

    // 填写数据和检验和
    uint8_t* data_pointer = txbuf.data + sizeof(icmp_hdr_t); // 移动到ip首部
    memcpy(data_pointer, recv_buf->data, sizeof(ip_hdr_t)+8);
    icmp_hdr->checksum16 = checksum16((uint16_t*)txbuf.data, txbuf.len);

    // 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}