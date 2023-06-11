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
        struct subuff *subCopy = allocTcpSub(lenToSend);

        sub_queue_tail(subsToSend, sub);
        sub_queue_tail(connection->retransmitQ, subCopy);

        sub_push(sub, lenToSend);
        sub_push(subCopy, lenToSend);

        memcpy(sub->data, buf, lenToSend);
        memcpy(subCopy->data, buf, lenToSend);

        buf += lenToSend;

        struct tcpHdr *hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);
        struct tcpHdr *hdrToSendCopy = (struct tcpHdr*) sub_push(subCopy, TCP_HDR_LEN);

        setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection) + lastSentPtr, connection->ackNum);
        setGeneralOptionsTcpHdr(hdrToSendCopy, connection, getSeqNum(connection) + lastSentPtr, connection->ackNum);

        hdrToSend->tcpAck = 1;
        hdrToSendCopy->tcpAck = 1;

        hdrToSend->tcpPsh = 1;
        hdrToSendCopy->tcpPsh = 1;

        hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN + lenToSend, IPP_TCP,
                                              htonl(connection->sock->srcaddr),
                                              htonl(connection->sock->dstaddr));
        hdrToSendCopy->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSendCopy, TCP_HDR_LEN + lenToSend, IPP_TCP,
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


int removeRecvdSubs(struct connection *connection) {

    bool acked = true;
    struct subuff *currSub;
    struct tcpHdr *currHdr;
    uint32_t lastByte;

    while(!sub_queue_empty(connection->retransmitQ) && acked) {
        currSub = sub_peek(connection->retransmitQ);

        currHdr = tcpHdrFromSub(currSub);
        if(currHdr == NULL) {
            return -1;
        }
        if(connection->lastRecvdAck > ntohl(currHdr->tcpSeqNum)) {
            sub_dequeue(connection->retransmitQ);
            free_sub(currSub);
        }
        else if((ntohl(currHdr->tcpSeqNum) - connection->lastRecvdAck) > WIN_SIZE && connection->lastRecvdAck != 0) {
            sub_dequeue(connection->retransmitQ);
            free_sub(currSub);
        }
        else {
            acked = false;
        }
    }
    return 0;   
}

int retransmitTcp(struct connection *connection) {

    removeRecvdSubs(connection);
    uint32_t lastSentSeq = getSeqNum(connection);
    struct subuff *currSub = sub_peek(connection->retransmitQ);
    if(sub_queue_empty(connection->retransmitQ)) {
        return 0;
    }
    struct tcpHdr *currHdr = tcpHdrFromSub(currSub);
        
        uint32_t lastByte = currSub->len - TCP_HDR_LEN;

        currSub = sub_peek(connection->retransmitQ);
        currHdr = tcpHdrFromSub(currSub);

        struct subuff *subCopy = allocTcpSub( ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8));
        sub_push(subCopy, ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8));
        memcpy(subCopy->data, currSub->data, currSub->len - TCP_HDR_LEN);
        struct tcpHdr *hdrToSendCopy = (struct tcpHdr*) sub_push(subCopy, TCP_HDR_LEN);
        setGeneralOptionsTcpHdr(hdrToSendCopy, connection, ntohl(currHdr->tcpSeqNum), connection->ackNum);
        hdrToSendCopy->tcpAck = 1;
        hdrToSendCopy->tcpPsh = 1;
        hdrToSendCopy->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSendCopy, TCP_HDR_LEN + (ANP_MTU_15_MAX_SIZE - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8)), IPP_TCP,
                                              htonl(connection->sock->srcaddr),
                                              htonl(connection->sock->dstaddr));

        

        int ret = ip_output(connection->sock->dstaddr, subCopy);
        if(connection->doubleAcks >= 3) {
            connection->doubleAcks = 0;
            free_sub(subCopy);
            return 0;
        }
        connection->windowSent += lastByte;
            if(connection->windowSent + MSS >= connection->peerWindowSize) {
                setWaitingForAck(connection, true);
            }

            if(getWaitingForAck(connection)) {
                int wait = waitForAck(connection);
                if(wait != 0) {
                    return(-1);
                }
                
            }
            
            usleep(1000);
        
        free_sub(subCopy);
    return 0;

}

int sendTcpData(struct connection *connection, const void *buf, size_t len) {
    struct subuff_head *subsToSend;
    int ret;
    int totalSent = 0;
    struct subuff *sending;
    size_t tcpWindow = (size_t )WIN_SIZE;
    while(len > 0) {
        if(len > tcpWindow) {
            subsToSend = dataSplit(connection, buf, tcpWindow);
            len -= tcpWindow;
        }
        else {
            subsToSend = dataSplit(connection, buf, len);
            len = 0;
        }

        while(!sub_queue_empty(subsToSend)) {
            sending = sub_dequeue(subsToSend);
            uint32_t lastByte = sending->len - TCP_HDR_LEN;

            struct tcpHdr *currSub = tcpHdrFromSub(sending);;

            setSeqNum(connection, getSeqNum(connection) + lastByte);
        
            connection->windowSent += lastByte;
            if(connection->windowSent + MSS >= connection->peerWindowSize || connection->windowSent + MSS >= WIN_SIZE) {
                setWaitingForAck(connection, true);
            }

            if(getWaitingForAck(connection)) {
                int wait = waitForAck(connection);
                if(wait == -1) {
                    int retransmision = retransmitTcp(connection);
                    if(retransmision != 0) {
                        for(int i = 0; i < 3; i ++){
                            retransmision = retransmitTcp(connection);
                            if(retransmision == 0) {
                                break;
                            }
                        }
                    }
                    wait = waitForAck(connection);
                    if(wait == -1) {
                        return wait;
                    }
                }
                else if(wait == 1) {
                    int retransmision = retransmitTcp(connection);
                    if(retransmision != 0) {
                        return retransmision;
                    }
                }
                usleep(1000); //necessary for congesiton management
            } 

            if(getIsLocal(connection)) {
                tcpRx(sending);
                ret = sending->len;
            }
            else {
            
                ret = ip_output(connection->sock->dstaddr, sending)-54; //tcp header size 54 != TCP_HDR_LEN
                if(ret < 0) {
                    return ret;
                }

            removeRecvdSubs(connection);        
            
            }

            totalSent += ret;
        
            if(!getIsLocal(connection)) {
                free_sub(sending);
            }
        }
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