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

struct socket* allocSock() {
    struct socket *newSock = (struct socket *) malloc(sizeof(struct socket));
    return newSock;
}