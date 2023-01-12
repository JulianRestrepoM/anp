#ifndef ANPNETSTACK_UDP_H
#define ANPNETSTACK_UDP_H

#include "systems_headers.h"
#include "socket.h"
#include "ip.h"
#include "config.h"
#include "utilities.h"
#include "connection.h"



struct udpHdr {

    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;
    uint8_t udpData[];

} __attribute__((packed));




struct subuff *allocUdpSub(int dataLen);
struct subuff_head *dataSplitUdp(struct connection *connection, const void *buf, size_t len);
int sendUdpData(struct connection *connection, const void *buf, size_t len);
int udpRx(struct subuff *sub);
struct udpHdr *udpHdrFromSub(struct subuff *sub);
int handlePacket(struct subuff *sub, struct socket *sock);

#define UDP_HDR_LEN sizeof(struct udpHdr)

#endif //ANPNETSTACK_UDP_H