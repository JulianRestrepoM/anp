#include "tcp.h"

int sendSyn(struct connection *connection) {
    struct subuff *sub = makeSynSub(connection);
    int ipOutputResult = ip_output(connection->sock->dstaddr, sub);
    int tries  = 3;

    while((ipOutputResult == -11) && (tries != 0)) {
        sleep(1);
        sub = makeSynSub(connection);
        ipOutputResult = ip_output(connection->sock->dstaddr, sub);
        tries--;
    }
    free_sub(sub);
    return ipOutputResult;
}

int sendAck(struct connection *connection, uint32_t ackNum) {

    if(getState(connection) != ESTABLISHED) {
        setSeqNum(connection, getSeqNum(connection) + 1);
    }

    struct subuff *sub = makeAckSub(connection, ackNum);
    int ipOutRes = ip_output(connection->sock->dstaddr, sub);
    free_sub(sub);
    return ipOutRes;
}

int sendFin(struct connection *connection) {

    // if(getState(connection) != ESTABLISHED) {
    //     setSeqNum(connection, getSeqNum(connection) + 1);
    // }

    struct subuff *sub = makeFinSub(connection);
    int ipOutRes = ip_output(connection->sock->dstaddr, sub);
    free_sub(sub);
    return ipOutRes;
}

struct subuff_head *dataSplit(struct connection *connection, const void *buf, size_t len) {
    int maxSendLen = ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8);
    int lenToSend = maxSendLen;
    int lastSentPtr = 0;

    if(len <= maxSendLen) { //if first packet is smaller than max send, then it sends maxsend instead of just len
        lenToSend = len;
    }


    struct subuff_head *subsToSend = (struct subuff_head *) malloc(sizeof(struct subuff_head));
    sub_queue_init(subsToSend);

    while(lastSentPtr < len) {
        struct subuff *sub = allocTcpSub(lenToSend);

        sub_queue_tail(subsToSend, sub);
        sub_push(sub, lenToSend);
        memcpy(sub->data, buf, lenToSend);
        buf += lenToSend;

        struct tcpHdr *hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);
        setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection) + lastSentPtr, getLastRecvSeq(connection));

        hdrToSend->tcpAck = 1;
        hdrToSend->tcpPsh = 1;
        hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN + lenToSend, IPP_TCP,
                                              htonl(connection->sock->srcaddr),
                                              htonl(connection->sock->dstaddr));

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

int sendTcpData(struct connection *connection, const void *buf, size_t len) {
    struct subuff_head *subsToSend = dataSplit(connection, buf, len);
    int ret;
    int totalSent = 0;
    struct subuff *sending;

    while(sub_queue_empty(subsToSend) == 0) {
        sending = sub_dequeue(subsToSend);
        uint32_t lastByte = sending->len - TCP_HDR_LEN;
        
        setSeqNum(connection, getSeqNum(connection) + lastByte);
        setWaitingForAck(connection, true);

        ret = ip_output(connection->sock->dstaddr, sending);
        if(ret < 0) {
            return ret;
        }

        int wait = waitForAck(connection);
        if(wait == -1) {
            return wait;
        }

        totalSent += ret;
        free_sub(sending);
    }
    return totalSent;
}