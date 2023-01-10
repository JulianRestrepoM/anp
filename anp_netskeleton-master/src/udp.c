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
        printf("HDR = %d Payload = %d total = %d\n", UDP_HDR_LEN, lenToSend, UDP_HDR_LEN + lenToSend);
       // hdrToSend->checksum = do_tcp_csum((uint8_t*)hdrToSend, UDP_HDR_LEN + lenToSend, IPPROTO_UDP, connection->sock->srcaddr, connection->sock->dstaddr); //make sure this is right
       hdrToSend->checksum = do_tcp_csum((uint8_t *)hdrToSend, UDP_HDR_LEN + lenToSend, IPP_UDP, 
                                        htonl(connection->sock->srcaddr), 
                                        htonl(connection->sock->dstaddr))+htons(6); //find out where im missing this 6

        printf("CHECLSUM IS %hx\n", ntohs(hdrToSend->checksum));
        // hdrToSend(":AND NOW %hx\n", )
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
            printf("ERROR: failed udp send A with %d\n", ret);
            for(int i = 0; i < 2; i++) {
                sleep(1);
                *sending = sendingCpy;
                ret = ip_output(connection->sock->dstaddr, sending);
                if(ret >= 0) {
                    printf("udb subsent\n");
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

int udpRx(struct subuff *sub) {
    // printf("Recived UDP packet\n");
    return 0;
}
