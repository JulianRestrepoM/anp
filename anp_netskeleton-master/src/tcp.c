#include "tcp.h"
#include <inttypes.h> // to print Uint_t numbers

void setGeneralOptionsTcpHdr(struct tcpHdr *hdr, struct connection *connection, uint32_t seqNum, uint32_t ackNum) {
    hdr->tcpSource = htons(connection->sock->srcport);
    hdr->tcpDest = connection->sock->dstport;
    hdr->tcpResPad1 = 0;
    hdr->tcpResPad2 = 0;
    hdr->tcpUrg = 0;
    hdr->tcpAck = 0;
    hdr->tcpPsh = 0;
    hdr->tcpRst = 0;
    hdr->tcpSyn = 0;
    hdr->tcpFin = 0;
    hdr->tcpAck = 0;
    hdr->tcpChecksum = 0;
    hdr->tcpWinSize = htons(WIN_SIZE);
    hdr->tcpLen = 5;
    hdr->tcpSeqNum = htonl(seqNum);
    hdr->tcpAckNum = htonl(ackNum);
}

struct tcpHdr *tcpHdrFromSub(struct subuff *sub) {
    return (struct tcpHdr *)(sub->head + ETH_HDR_LEN + IP_HDR_LEN);
}

void setSynOptionsTcpHdr(struct subuff *sub, struct connection *connection) {
    struct tcpHdr* hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);

    setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection), 0);

    hdrToSend->tcpSyn = 1;
    hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN, IPP_TCP,
                                          htonl(connection->sock->srcaddr),
                                          htonl(connection->sock->dstaddr));
                                          
}

void setSynAckOptionsTcpHdr(struct subuff *sub, struct connection *connection) {
    struct tcpHdr* hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);

    setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection), getLastRecvSeq(connection)+1);

    hdrToSend->tcpSyn = 1;
    hdrToSend->tcpAck = 1;
    hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN, IPP_TCP,
                                          htonl(connection->sock->srcaddr),
                                          htonl(connection->sock->dstaddr));
                                          
}

void setAckOptionsTcpHdr(struct subuff *sub, struct connection *connection, uint32_t ackNum) {
    struct tcpHdr* hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);
    
    setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection), ackNum);

    hdrToSend->tcpAck = 1;
    hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN, IPP_TCP,
                                          htonl(connection->sock->srcaddr),
                                          htonl(connection->sock->dstaddr));
}

void setFinOptionsTcpHdr(struct subuff *sub, struct connection *connection, uint32_t ackNum) {
    struct tcpHdr* hdrToSend = (struct tcpHdr*) sub_push(sub, TCP_HDR_LEN);

    setGeneralOptionsTcpHdr(hdrToSend, connection, getSeqNum(connection), ackNum);

    hdrToSend->tcpFin = 1;
    hdrToSend->tcpAck = 1;
    hdrToSend->tcpChecksum = do_tcp_csum((uint8_t *) hdrToSend, TCP_HDR_LEN, IPP_TCP,
                                          htonl(connection->sock->srcaddr),
                                          htonl(connection->sock->dstaddr));
}

struct subuff *allocTcpSub(int dataLen) {
    unsigned int totalSize = IP_HDR_LEN + ETH_HDR_LEN + TCP_HDR_LEN + dataLen;
    struct subuff *sub = alloc_sub(totalSize);
    sub_reserve(sub, totalSize);
    sub->protocol = IPP_TCP;
    return sub;
}

struct subuff *makeSynSub(struct connection *connection) {
    struct subuff *sub = allocTcpSub(0);
    setSynOptionsTcpHdr(sub, connection);
    return sub;
}

struct subuff *makeSynAckSub(struct connection *connection) {
    struct subuff *sub = allocTcpSub(0);
    setSynAckOptionsTcpHdr(sub, connection);
    return sub;
}

struct subuff *makeAckSub(struct connection *connection, uint32_t ackNum) {
    struct subuff *sub = allocTcpSub(0);
    setAckOptionsTcpHdr(sub, connection, ackNum);
    return sub;
}

struct subuff *makeFinSub(struct connection *connection) {
    // uint32_t ackNum = getLastRecvSeq(connection) + 1;
     uint32_t ackNum = getLastRecvSeq(connection); //todo: this fixed the close with iperf, idk if it broke it with reddit maybe
    struct subuff *sub = allocTcpSub(0);
    setFinOptionsTcpHdr(sub, connection, ackNum);
    return sub;
}

void waitForSynAck(struct connection *connection) {
    struct timespec timeToWait = {0,0};
    int now = clock_gettime(CLOCK_REALTIME, &timeToWait);

    if(now != 0) {
        printf("clock failed\n");
        return;
    }

    timeToWait.tv_sec += 1; //wait for 1 second
    pthread_mutex_lock(&connection->connectionLock);
    int ret = pthread_cond_timedwait(&connection->synackRecv, &connection->connectionLock, &timeToWait);
    pthread_mutex_unlock(&connection->connectionLock);
    
    if(ret == ETIMEDOUT) {
        return;
    }
    setState(connection, SYN_SENT);

}

int waitForAck(struct connection *connection) {
    struct timespec timeToWait = {0,0};
    int now = clock_gettime(CLOCK_REALTIME, &timeToWait);

    if(now != 0) {
        printf("clock failed\n");
        return -1;
    }

    timeToWait.tv_sec += 1; //wait for 1 second
    pthread_mutex_lock(&connection->connectionLock);
    int ret = pthread_cond_timedwait(&connection->ackRecv, &connection->connectionLock, &timeToWait);
    pthread_mutex_unlock(&connection->connectionLock);
    
    if(ret == ETIMEDOUT) {
        printf("error: no ack received\n");
        // return -1; //todo: i think theres is some locking/cuncurrent issues, that makes it think it did not recieve an ack
    }
    return 0;
}

int waitForFinACk(struct connection *connection) {
    struct timespec timeToWait = {0, 0};
    int now = clock_gettime(CLOCK_REALTIME, &timeToWait);

    if (now != 0) {
        printf("clock failed\n");
        return -1;
    }

    timeToWait.tv_sec += 1; //wait for 1 second
    pthread_mutex_lock(&connection->connectionLock);
    int ret = pthread_cond_timedwait(&connection->finAckRecv, &connection->connectionLock, &timeToWait);
    pthread_mutex_unlock(&connection->connectionLock);
    
    if(ret == ETIMEDOUT) {
        printf("error: no fin ack received\n");
        return -1;
    }
    return 0;
}

int doTcpHandshake(struct connection *connection) {

    if(getState(connection) != CLOSED) {
        printf("error: connection already initiated\n");
    }
    int synCode = sendSyn(connection);

    if(synCode < 0) {
        printf("error: syn failed, ip_output code %d\n", synCode);
        return -1;
    }

    waitForSynAck(connection);
    if(getSynAckRecv2(connection)) { //learn signaling check 04/10/2022 journal
        setState(connection, SYN_SENT);
    }
    if(getState(connection) != SYN_SENT) {
        printf("handshake state %d\n", getState(connection));
        printf("error: Synack timeout\n");
        return -1;
    }

    setLastRecvSeqNum(connection, getLastRecvSeq(connection) + 1);
    int ackCode = sendAck(connection, getLastRecvSeq(connection));
    if(ackCode >= 0) {
        setState(connection, ESTABLISHED);
    }
    else {
        printf("error: ACK failed, ip_output code %d\n", ackCode);
        return -1;
    }
    return 0;
}

int doTcpClose(struct connection *connection) {
    int currState = getState(connection);
    if(currState == ESTABLISHED) {
        int ret = sendFin(connection);
        if(ret < 0) {
            printf("sending fin failed\n");
            return ret;
        }
        setState(connection, FIN_WAIT_1);
        ret = waitForFinACk(connection);
        if (ret < 0) {
            return ret;
        }   
        setState(connection, FIN_WAIT_2);
        setState(connection, TIME_WAIT);

        ret = sendAck(connection, getLastRecvSeq(connection) + 1);
        if(ret < 0 ) {
            printf("ack failed to send\n");
            return ret;
        }
        setState(connection, CLOSED);
        return 0;
    }
    else if(currState == LAST_ACK) {
        return 0;
    }
    else {
        printf("Connection not established\n");
        return -1;
    }
   
}

int getData(struct connection *connection, void *buf, size_t len) { //TODO: i think im clearing the buffer while there is still data i need to read in. since wget calls small reads at a time
    size_t lenRecv = 0;
    struct subuff *current;
    struct iphdr *ipHdr;
    size_t currentSize;

    // if(connection->sock->isNonBlocking && len < connection->buffedAmount) {
    //     printf("NOT blOCKED A\n");
    //             errno = EAGAIN;
    //             // printf("Q LENgth get nodata %ld\n", sub_queue_len(connection->recvPkts));
    //             return -1;
    //             return lenRecv; //prob should also return errnos
    // }

    while(lenRecv < len) {
        
        // pthread_mutex_lock(&connection->connectionLock);
        if(!sub_queue_empty(connection->sock->recvPkts)) {
            while(!sub_queue_empty(connection->sock->recvPkts) && lenRecv < len) {
                current = sub_peek(connection->sock->recvPkts);
                // pthread_mutex_unlock(&connection->connectionLock);
                ipHdr = IP_HDR_FROM_SUB(current);

                //TODO: it seems to only save max 536 at a time. and overwrites first half of packet larger
                currentSize = IP_PAYLOAD_LEN(ipHdr) - TCP_HDR_LEN - current->read;
                void *src = current->head + IP_HDR_LEN + ETH_HDR_LEN + TCP_HDR_LEN + current->read;
                void *dest = buf + lenRecv;
                 
                
                if((currentSize + lenRecv) > len ) {
                    currentSize = len -lenRecv;
                    lenRecv += currentSize;
                    memcpy(dest, src, currentSize);
                }
                else {
                    memcpy(dest, src, currentSize);
                    lenRecv += currentSize;
                }
                if(current->len >= currentSize) {
                    sub_dequeue(connection->sock->recvPkts);
                    free_sub(current);
                }
                else {
                    int read = current->read;
                    read += currentSize;
                    current->read = read;
                }
                    
            }
        }
        else {
            // pthread_mutex_unlock(&connection->connectionLock);
            // sleep(1);
            // i++;
            // if(i > 5) {
            //     printf("getData Timed out\n");
            //     return lenRecv;
            // }
            if(connection->sock->isNonBlocking) {
                errno = EAGAIN;
                // printf("Q LENgth get nodata %ld\n", sub_queue_len(connection->recvPkts));
                // return -1;
                return lenRecv; //prob should also return errnos
            }
        }
    }
    // printf("Q LENgth get data %ld\n", sub_queue_len(connection->recvPkts));
    return lenRecv;
}

int getDataTest(struct connection *connection, void *buf, size_t len) { //TODO: i think im clearing the buffer while there is still data i need to read in. since wget calls small reads at a time
    size_t lenRecv = 0;
    struct subuff *current;
    struct iphdr *ipHdr;
    size_t currentSize;

    while(lenRecv < len) {
        
        // pthread_mutex_lock(&connection->connectionLock);
        if(!sub_queue_empty(connection->sock->recvPkts)) {
            while(!sub_queue_empty(connection->sock->recvPkts) && lenRecv < len) {
                current = sub_peek(connection->sock->recvPkts);
                // pthread_mutex_unlock(&connection->connectionLock);
                ipHdr = IP_HDR_FROM_SUB(current);

                //TODO: it seems to only save max 536 at a time. and overwrites first half of packet larger
                currentSize = IP_PAYLOAD_LEN(ipHdr) - TCP_HDR_LEN - current->read;
                void *src = current->head + IP_HDR_LEN + ETH_HDR_LEN + TCP_HDR_LEN + current->read;
                void *dest = buf + lenRecv;
                 
                
                if((currentSize + lenRecv) > len ) {
                    currentSize = len -lenRecv;
                    lenRecv += currentSize;
                    memcpy(dest, src, currentSize);
                }
                else {
                    memcpy(dest, src, currentSize);
                    lenRecv += currentSize;
                }
                if(current->len >= currentSize) {
                    sub_dequeue(connection->sock->recvPkts);
                    free_sub(current);
                }
                else {
                    int read = current->read;
                    read += currentSize;
                    current->read = read;
                }
                    
            }
        }
        // else {
        //     pthread_mutex_unlock(&connection->connectionLock);
        // }
    }
    return lenRecv;
}

