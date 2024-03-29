#include "udp.h"

int udpRx(struct subuff *sub) {

    struct udpHdr *hdr = udpHdrFromSub(sub);
    struct socket *sock = getSocketByPort((hdr->destinationPort));
    if(sock == NULL) {
        free_sub(sub);
        return 0;
    }

    return handlePacket(sub, sock);
}

int handlePacket(struct subuff *sub, struct socket *sock) {
    pthread_mutex_lock(&sock->sock_lock);
    sub_queue_tail(sock->recvPkts, sub);

     struct iphdr *ipHdr = IP_HDR_FROM_SUB(sub);
     int payload =  IP_PAYLOAD_LEN(ipHdr) - UDP_HDR_LEN;
     sock->readAmount += payload;
     pthread_mutex_unlock(&sock->sock_lock);
     

    return 0;

}