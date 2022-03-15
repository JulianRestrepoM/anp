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
    newSocket->fileDescriptor = sockHead.highestFd;

    listAdd(newSocket);

    return newSocket;
}

void initSocketList() {
    sockHead.listHead = (struct list_head *) malloc(sizeof(struct list_head));
    sockHead.highestFd = 10000;
    list_init(sockHead.listHead);
}

void listAdd(struct socket *newSocket) {
    list_add(&newSocket->list, sockHead.listHead);
}