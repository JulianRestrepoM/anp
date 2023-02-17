#include "udp.h"

struct subuff *allocUdpSub(int dataLen) {
    unsigned int totalSize = IP_HDR_LEN + ETH_HDR_LEN + UDP_HDR_LEN + dataLen;
    struct subuff *sub = alloc_sub(totalSize);
    sub_reserve(sub, totalSize);
    sub->protocol = IPPROTO_UDP;
    return sub;
}

struct subuff_head *dataSplitUdp(struct connection *connection, const void *buf, size_t len) {
    int maxSendLen = ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8);
    int lenToSend = maxSendLen;
    int lastSentPtr = 0;

    if(len <= maxSendLen) { //if first packet is smaller than max send, then it sends maxsend instead of just len
        lenToSend = len;
    }

    struct subuff_head *subsToSend = (struct subuff_head *) malloc(sizeof(struct subuff_head));
    sub_queue_init(subsToSend);

    while(lastSentPtr < len) {
        struct subuff *sub = allocUdpSub(lenToSend);
        sub_queue_tail(subsToSend, sub);
        sub_push(sub, lenToSend);
        memcpy(sub->data, buf, lenToSend);
        buf += lenToSend;

        struct udpHdr *hdrToSend = (struct udpHdr*) sub_push(sub, UDP_HDR_LEN);
        hdrToSend->sourcePort = htons(connection->sock->srcport);
        hdrToSend->destinationPort = connection->sock->dstport;
        hdrToSend->checksum = 0;
        hdrToSend->length =htons(UDP_HDR_LEN + lenToSend); // make sure this means what i mean it means
        hdrToSend->checksum = 0;
        lastSentPtr += lenToSend;

        if((len - lastSentPtr) > maxSendLen) {
            lenToSend = maxSendLen;
        }
        else {
            lenToSend = (len - lastSentPtr);
        }
    }
    return subsToSend;
}

int sendUdpData(struct connection *connection, const void *buf, size_t len) {
    struct subuff_head *subsToSend = dataSplitUdp(connection, buf, len);
    int ret;
    int totalSent = 0;
    struct subuff *sending;

    while(sub_queue_empty(subsToSend) == 0) {
        sending = sub_dequeue(subsToSend);
        struct subuff sendingCpy = *sending;
        ret = ip_output(connection->sock->dstaddr, sending);
        if(ret < 0) {
            // printf("ERROR: failed udp send A with %d\n", ret);
            for(int i = 0; i < 2; i++) {
                sleep(1);
                *sending = sendingCpy;
                ret = ip_output(connection->sock->dstaddr, sending);
                if(ret >= 0) {
                    // printf("udb subsent\n");
                    goto subSent;
                }
            }
            printf("ERROR: failed udp send B with %d\n", ret);
            return ret;
        }
    
        subSent:
        totalSent += ret;
        free_sub(sending);
    }
    return totalSent;
}

struct udpHdr *udpHdrFromSub(struct subuff *sub) {
    return (struct udpHdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
}

int getUdpData(struct socket *sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {

    size_t lenRecv = 0;
    struct subuff *current;
    struct iphdr *ipHdr;
    size_t currentSize;
    
    if(flags != 0) {
        printf("oh oh Ive got flags\n");
        return -1;
    }
    pthread_mutex_lock(&sock->sock_lock);
    if(src_addr != NULL) {
        // printf("got address\n");
        if(!sub_queue_empty(sock->recvPkts)) {
            current = sub_peek(sock->recvPkts);
            struct sockaddr_in *sin = (struct sockaddr_in *)src_addr;
            sin->sin_port = sock->dstport;
            sin->sin_addr.s_addr = htonl(sock->dstaddr);
            sin->sin_family = sock->domain;
            memcpy(&src_addr, &sin, sizeof(sin));

            *addrlen = sock->dstaddrlen;   
        }
    }

    if(!sub_queue_empty(sock->recvPkts)) {
        current = sub_dequeue(sock->recvPkts);
        ipHdr = IP_HDR_FROM_SUB(current);

        currentSize = IP_PAYLOAD_LEN(ipHdr) - UDP_HDR_LEN - current->read;
        void *src = current->head + IP_HDR_LEN + ETH_HDR_LEN + UDP_HDR_LEN + current->read;
        void *dest = buf + lenRecv;

        lenRecv += currentSize;
        memcpy(dest, src, currentSize);
        free_sub(current);
    }
    sock->readAmount -= lenRecv;
    pthread_mutex_unlock(&sock->sock_lock);
    return lenRecv;
}
