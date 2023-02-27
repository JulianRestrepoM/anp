#include "tcp.h"

int sendSyn(struct connection *connection) {
    struct subuff *sub = makeSynSub(connection);
    if(getIsLocal(connection)) {
        tcpRx(sub);
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
        tcpRx(sub);
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
        tcpRx(sub);
        return 0;
    }

    int ipOutRes = ip_output(connection->sock->dstaddr, sub);
    free_sub(sub);
    return ipOutRes;
}

int sendFin(struct connection *connection) {

    struct subuff *sub = makeFinSub(connection);
    if(getIsLocal(connection)) {
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
        setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection) + lastSentPtr, connection->ackNum);

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
    // connection->windowSent = 0;

    while(!sub_queue_empty(subsToSend)) {
        sending = sub_dequeue(subsToSend);
        uint32_t lastByte = sending->len - TCP_HDR_LEN;

        struct tcpHdr *currSub = tcpHdrFromSub(sending);
        currSub->tcpSeqNum = htonl(getSeqNum(connection));
        // printf("SENDINGING SEQ %d\n", ntohl(currSub->tcpSeqNum));

        setSeqNum(connection, getSeqNum(connection) + lastByte);
        
        connection->windowSent += lastByte;
        // printf("WINDOW SENT %d window max %d\n",connection->windowSent, connection->peerWindowSize);
        if(connection->windowSent + MSS >= connection->peerWindowSize) {
            // printf("WINDOWSENT = %d PEER WINDOW = %d\n", connection->windowSent, connection->peerWindowSize);
            setWaitingForAck(connection, true);
            // printf("waiting\n");
            // while(connection->windowSent > 0) {
            //     sleep(1);
            //     printf("NOT 0\n");
            // }
        }

          if(getWaitingForAck(connection)) {
            // printf("waiting for ack\n");
            int wait = waitForAck(connection);
            if(wait == -1) {
                printf("Wait failed\n");
                return wait;
            }
            usleep(1000);
        }

        if(getIsLocal(connection)) {
            tcpRx(sending);
            ret = sending->len;
        }
        else {
            
            ret = ip_output(connection->sock->dstaddr, sending)-54; //tcp header size 54 != TCP_HDR_LEN
            // printf("out with %ld\n",ntohl(currSub->tcpSeqNum));
            // printf("packet out %d\n", connection->windowSent);
            if(ret < 0) {
                return ret;
            }
        }

        totalSent += ret;
        
        
      
        
        if(!getIsLocal(connection)) {
            free_sub(sending);
        }
    }
    // connection->windowSent = 0;
    
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