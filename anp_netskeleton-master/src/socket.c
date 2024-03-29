#include "socket.h"

struct socket *createSocket(int domain, int type, int protocol) {

    if(sockHead.listHead == NULL) {
        initSocketList();
    }

    struct socket *newSocket = (struct socket *) malloc(sizeof(struct socket));

    sockHead.highestFd++;

    newSocket->domain = domain;
    newSocket->type = type;
    newSocket->protocol = protocol;
    newSocket->fd = sockHead.highestFd;
    newSocket->srcaddr = 0;
    newSocket->pendingC = NULL;
    newSocket->isNonBlocking = false;
    newSocket->recvPkts = (struct subuff_head *) malloc(sizeof(struct subuff_head));
    newSocket->readAmount = 0;
    sub_queue_init(newSocket->recvPkts);
    pthread_mutex_init(&newSocket->sock_lock, NULL);

    sockListAdd(newSocket);

    return newSocket;
}

void initSocketList() {
    sockHead.listHead = (struct list_head *) malloc(sizeof(struct list_head));
    sockHead.highestFd = ANP_SOCKET_MIN_VAL;
    list_init(sockHead.listHead);
}

void sockListAdd(struct socket *newSocket) {
    list_add(&newSocket->list, sockHead.listHead);
}

void sockListRemove(struct socket *toDelete) {
    list_del(&toDelete->list);
    free(toDelete);
}

bool isFdUsed(int fd) {
    struct list_head *theFd;
    struct socket *currSocket;
    if(sockHead.listHead == NULL) {
        return false;
    }
    list_for_each(theFd, sockHead.listHead) {
        currSocket = list_entry(theFd, struct socket, list);
        if(currSocket->fd == fd) {
            return true;
        }
    }
    return false;
}

struct socket *getSocketByFd(int fd) {
    if(sockHead.listHead == NULL) {
        return NULL;
    }
    struct list_head *theFd;
    struct socket *currSocket;
    list_for_each(theFd, sockHead.listHead) {
        currSocket = list_entry(theFd, struct socket, list);
        if(currSocket->fd == fd) {
            return currSocket;
        }
    }
    return NULL;
}

struct socket *getSocketByPort(int port) {
    if(sockHead.listHead == NULL) {
        return NULL;
    }
    struct list_head *socketLst;
    struct socket *currSocket;
    list_for_each(socketLst, sockHead.listHead) {
        currSocket = list_entry(socketLst, struct socket, list);
        if(currSocket->srcport == ntohs(port)) {
            return currSocket;
        }
    }
    return NULL;
}

struct socket* allocSock() {
    struct socket *newSock = (struct socket *) malloc(sizeof(struct socket));
    return newSock;
}