#include "tcp.h"

int sendSyn(struct connection *connection) {
    struct subuff *sub = makeSynSub(connection);
    if(getIsLocal(connection)) {
        printf("sendSynLocal\n");
        tcpRx(sub); //TODO: doing it on TCP level might not be enough. Might need to do it on IP level instead
        // free_sub(sub);
        return 0;
    }
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

int sendSynAck(struct connection *connection) {
    struct subuff *sub = makeSynAckSub(connection);

    if(getIsLocal(connection)) {
        printf("sendSynAck Local\n");
        tcpRx(sub);
        // free_sub(sub);
        return 0;
    }

    int ipOutputResult = ip_output(connection->sock->dstaddr, sub);
    int tries  = 3;

    while((ipOutputResult == -11) && (tries != 0)) {
        sleep(1);
        sub = makeSynAckSub(connection);
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

    if(getIsLocal(connection)) {
        printf("sendAck Local\n");
        tcpRx(sub);
        return 0;
    }

    int ipOutRes = ip_output(connection->sock->dstaddr, sub);
    free_sub(sub);
    return ipOutRes;
}

int sendFin(struct connection *connection) {

    // if(getState(connection) != ESTABLISHED) {
    //     setSeqNum(connection, getSeqNum(connection) + 1);
    // }

    struct subuff *sub = makeFinSub(connection);
    if(getIsLocal(connection)) {
        printf("sendAck Local\n");
        tcpRx(sub);
        return 0;
    }
    int ipOutRes = ip_output(connection->sock->dstaddr, sub);
    free_sub(sub);
    return ipOutRes;
}

struct subuff_head *dataSplit(struct connection *connection, const void *buf, size_t len) {
    int maxSendLen = ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8);
    if(maxSendLen > WIN_SIZE) {
        maxSendLen = WIN_SIZE;
    }
    int lenToSend = maxSendLen;
    unsigned int lastSentPtr = 0;
    unsigned int theLen =  (unsigned int)len;

    if(theLen <= maxSendLen) { //if first packet is smaller than max send, then it sends maxsend instead of just len
        lenToSend = len;
    }


    struct subuff_head *subsToSend = (struct subuff_head *) malloc(sizeof(struct subuff_head));
    sub_queue_init(subsToSend);

    while(lastSentPtr < theLen) {
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

        if((theLen - lastSentPtr) > maxSendLen) {
            lenToSend = maxSendLen;
        }
        else {
            lenToSend = (theLen - lastSentPtr);
        }
    }
    return subsToSend;
}

int sendTcpData(struct connection *connection, const void *buf, size_t len) {
    struct subuff_head *subsToSend = dataSplit(connection, buf, len);
    int ret;
    int totalSent = 0;
    struct subuff *sending;
    int i = 0;

    while(sub_queue_empty(subsToSend) == 0) {
        sending = sub_dequeue(subsToSend);
        uint32_t lastByte = sending->len - TCP_HDR_LEN;
        
        setSeqNum(connection, getSeqNum(connection) + lastByte);
        setWaitingForAck(connection, true);

        ret = ip_output(connection->sock->dstaddr, sending);
        if(ret < 0) {
            return ret;
        }
        if(getWaitingForAck(connection)) {
            int wait = waitForAck(connection);
            if(wait == -1) {
                return wait;
            }
        }
        totalSent += ret;
        free_sub(sending);
        i++;
    }
    return totalSent;
}

int sendTcpDataTest(struct connection *connection, const void *buf, size_t len) {
    struct subuff_head *subsToSend = dataSplit(connection, buf, len);
    int ret;
    int totalSent = 0;
    struct subuff *sending;

    while(sub_queue_empty(subsToSend) == 0) {
        sending = sub_dequeue(subsToSend);
        uint32_t lastByte = sending->len - TCP_HDR_LEN;

        setSeqNum(connection, getSeqNum(connection) + lastByte);

        ret = ip_output(connection->sock->dstaddr, sending);
        if(ret < 0) {
            return ret;
        }
        
        totalSent += ret;
        free_sub(sending);
    }
    return totalSent;
}