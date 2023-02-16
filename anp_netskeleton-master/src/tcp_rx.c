#include "tcp.h"
#include <inttypes.h> // to print Uint_t numbers

int tcpRx(struct subuff *sub) { 
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    if((hdr->tcpAck == 1) && (hdr->tcpSyn == 1)) {
        return handleSynAck(sub);
    }
    if((hdr->tcpPsh == 1)&& (hdr->tcpFin == 1)) { //servre sends F with last bit of data
        return handleAck(sub);
    }
    if((hdr->tcpAck == 1) && (hdr->tcpFin == 1)) {
        return handleFinAck(sub);
    }
    if(hdr->tcpAck == 1) {
        return handleAck(sub);
    }
    if(hdr->tcpSyn == 1) {
        handleSyn(sub);
    }
    else {
        free_sub(sub);
        return -1;
    }
}

int handleSyn(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);

    struct socket *serverSocket = getSocketByPort(htons(hdr->tcpDest));
    if(serverSocket == NULL) {
        printf("ERROR: handleSyn did not find socketServer\n");
        goto dropPkt;
    }
    if(!serverSocket->isPassive) {
        printf("ERROR handleSyn: serverSocket not passive\n");
        goto dropPkt;
    }
    if(serverSocket->pendingC) {
        printf("ERROR: handleSyn: backlog full\n");
        goto dropPkt;
    }

    int newSockFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct socket *newSocket = getSocketByFd(newSockFd);
    newSocket->srcport = genRandomPort();
    newSocket->dstport = ntohs(hdr->tcpSource);
     //create a connection struct for the server
    if (connectionHead.connectionListHead == NULL) 
    {
        initConnectionList();
    }
    struct connection *newConnection = allocConnection();
    addNewConnection(newConnection, newSocket);

    setState(newConnection, SYN_RECIEVED);
    newConnection->ackNum = ntohl(hdr->tcpSeqNum);
    newConnection->peerWindowSize = ntohs(hdr->tcpWinSize);
    
    if(findConnectionbyPort(ntohs(newSocket->dstport))) {
        newConnection->isLocalConnection = true;
    }
    else {
        newConnection->isLocalConnection = false;
    }

    sendSynAck(newConnection);
    setWaitingForAck(newConnection, true);
    if(getWaitingForAck(newConnection)) {
        int wait = waitForAck(newConnection);
        if(wait == -1) {
            return wait;
        }
    }
    setState(newConnection, ESTABLISHED);
    serverSocket->pendingC = newConnection;
    return 0;

    dropPkt:
    free_sub(sub);
    return -1;
}

int handleAck(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    uint32_t ackNum = ntohl(hdr->tcpAckNum);
    struct connection *incomingConnection = findConnectionbyPort(hdr->tcpDest);

    struct iphdr *ipHdr = IP_HDR_FROM_SUB(sub);
    size_t currentSize = IP_PAYLOAD_LEN(ipHdr) - TCP_HDR_LEN;

    if(incomingConnection == NULL) {
        goto dropPkt;
    }

    if(currentSize == 0) {
        if(getWaitingForAck(incomingConnection) == true) {
            if(ackNum == getSeqNum(incomingConnection)) {
                setWaitingForAck(incomingConnection, false);
                free_sub(sub);
                return 0;
            }
        }
        incomingConnection->windowSent = 0;
        free_sub(sub);
        return 0;
    }
    
    else if(getSeqNum(incomingConnection) == ackNum -1) {
        return handleFinAck(sub);
    }
    else if(ntohl(hdr->tcpSeqNum) == incomingConnection->ackNum) {
        return handleRecv(incomingConnection, sub, hdr);
    }
    dropPkt:
    free_sub(sub);
    return -1;
}

int handleRecv(struct connection *incomingConnection, struct subuff *sub, struct tcpHdr *hdr) {
    struct iphdr *ipHdr = IP_HDR_FROM_SUB(sub);
    size_t currentSize = IP_PAYLOAD_LEN(ipHdr) - TCP_HDR_LEN;
    
    pthread_mutex_lock(&incomingConnection->sock->sock_lock);
    sub_queue_tail(incomingConnection->sock->recvPkts, sub);
    pthread_mutex_unlock(&incomingConnection->sock->sock_lock);
    incomingConnection->sock->readAmount += currentSize;

    incomingConnection->ackNum = ntohl(hdr->tcpSeqNum) + currentSize;
    int ret = sendAck(incomingConnection, incomingConnection->ackNum);
        if(ret < 0) {
            printf("failed to send ACK\n");
            return -1;
        } 
    return 0;
}

int handleSynAck(struct subuff *sub) {
    struct tcpHdr *hdr = tcpHdrFromSub(sub);
    uint32_t ackNum = ntohl(hdr->tcpAckNum);
    struct connection *incomingConnection = findConnectionBySeqNum(ackNum - 1);

    if(incomingConnection == NULL) {
        goto dropPkt;
    }
    if(getState(incomingConnection) == SYN_SENT) {
        goto dropPkt;
    }
    incomingConnection->ackNum = ntohl(hdr->tcpSeqNum);
    incomingConnection->peerWindowSize = ntohs(hdr->tcpWinSize);

    pthread_mutex_lock(&incomingConnection->connectionLock);
    pthread_cond_signal(&incomingConnection->synackRecv);
    pthread_mutex_unlock(&incomingConnection->connectionLock);

    setSynAckRecv2(incomingConnection, true);

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
        if((incomingConnection = findConnectionBySeqNum(ackNum)) != NULL) { //TODO: Actually having this work properlly is probably important lol
            setState(incomingConnection, CLOSE_WAIT);
            sendAck(incomingConnection, incomingConnection->ackNum+1);
            sendFin(incomingConnection);
            setState(incomingConnection, LAST_ACK);
            free_sub(sub);
            return 0;
        }
        goto dropPkt;
    }
    if(getState(incomingConnection) == SYN_SENT) {
        goto dropPkt;
    }
    incomingConnection->ackNum = ntohl(hdr->tcpSeqNum);
    pthread_mutex_lock(&incomingConnection->connectionLock);
    pthread_cond_signal(&incomingConnection->finAckRecv);
    pthread_mutex_unlock(&incomingConnection->connectionLock);

    free_sub(sub);
    return 0;

    dropPkt:
    free_sub(sub);
    return -1;
}