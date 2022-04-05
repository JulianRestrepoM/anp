#include "tcp.h"

int tcpRx(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    if((hdr->tcpAck == 1) && (hdr->tcpSyn == 1)) {
        return handleSynAck(sub);
    }
    if((hdr->tcpAck == 1) && (hdr->tcpFin == 1)) {
        return handleFinAck(sub);
    }
    if(hdr->tcpAck == 1) {
        return handleAck(sub);
    }
}

int handleAck(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    uint32_t ackNum = ntohl(hdr->tcpAckNum);
    struct connection *incomingConnection = findConnectionBySeqNum(ackNum);

    if((incomingConnection != NULL) && (getWaitingForAck(incomingConnection) == true)) {
        setLastRecvSeqNum(incomingConnection, ntohl(hdr->tcpSeqNum));
        setWaitingForAck(incomingConnection, false);

        pthread_mutex_lock(&incomingConnection->connectionLock);
        pthread_cond_signal(&incomingConnection->ackRecv);
        pthread_mutex_unlock(&incomingConnection->connectionLock);
        return 0;
    }
    else if(incomingConnection == NULL) {
        printf("error: could not find connection\n");
        goto dropPkt;
    }
    else {
        return handleRecv(incomingConnection, sub, hdr);
    }
    dropPkt:
    free_sub(sub);
    return -1;
}

int handleRecv(struct connection *incomingConnection, struct subuff *sub, struct tcpHdr *hdr) {
    setLastRecvSeqNum(incomingConnection, ntohl(hdr->tcpSeqNum));

    pthread_mutex_lock(&incomingConnection->connectionLock);
    sub_queue_tail(incomingConnection->recvPkts, sub);
    pthread_mutex_unlock(&incomingConnection->connectionLock);

    return 0;
}

int handleSynAck(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    uint32_t ackNum = ntohl(hdr->tcpAckNum);
    struct connection *incomingConnection = findConnectionBySeqNum(ackNum - 1);

    if(incomingConnection == NULL) {
        printf("Connection not found, invalid ACK\n");
        goto dropPkt;
    }
    if(getState(incomingConnection) == SYN_SENT) {
        printf("already recieved this\n");
        goto dropPkt;
    }
    setLastRecvSeqNum(incomingConnection, ntohl(hdr->tcpSeqNum));

    pthread_mutex_lock(&incomingConnection->connectionLock);
    pthread_cond_signal(&incomingConnection->synackRecv);
    pthread_mutex_unlock(&incomingConnection->connectionLock);

    free_sub(sub);
    return 0;

    dropPkt:
    free_sub(sub);
    return -1;
}

int handleFinAck(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    uint32_t ackNum = ntohl(hdr->tcpAckNum);
    struct connection *incomingConnection = findConnectionBySeqNum(ackNum - 1);

    if(incomingConnection == NULL) {
        printf("Connection not found, invalid ACK\n");
        goto dropPkt;
    }
    if(getState(incomingConnection) == SYN_SENT) {
        printf("already received this\n");
        goto dropPkt;
    }

    setLastRecvSeqNum(incomingConnection, ntohl(hdr->tcpSeqNum));

    pthread_mutex_lock(&incomingConnection->connectionLock);
    pthread_cond_signal(&incomingConnection->finAckRecv);
    pthread_mutex_unlock(&incomingConnection->connectionLock);

    free_sub(sub);
    return 0;

    dropPkt:
    free_sub(sub);
    return -1;
}