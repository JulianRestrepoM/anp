#include "udp.h"

int udpRx(struct subuff *sub) {

    struct udpHdr *hdr = udpHdrFromSub(sub);
    struct socket *sock = getSocketByPort((hdr->destinationPort));
    if(sock == NULL) {
        printf("UDP packet not mine, dropping\n");
        free_sub(sub);
        return 0;
    }

    return handlePacket(sub, sock);
}

int handlePacket(struct subuff *sub, struct socket *sock) {
    sub_queue_tail(sock->recvPkts, sub);

     struct iphdr *ipHdr = IP_HDR_FROM_SUB(sub);
     int payload =  IP_PAYLOAD_LEN(ipHdr) - UDP_HDR_LEN;
     sock->readAmount += payload;
     

    return 0;

}