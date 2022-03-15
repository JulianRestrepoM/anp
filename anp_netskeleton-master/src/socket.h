#ifndef ANPNETSTACK_SOCKET_H
#define ANPNETSTACK_SOCKET_H
#include "linklist.h"
#include "systems_headers.h"


struct socket {
    struct list_head list;
    int domain;
    int type;
    int protocol;
    int fileDescriptor;
};

typedef struct SOCKET_HEAD {
    int highestFd;
    struct list_head *listHead;
} socket_head;

socket_head sockHead;

struct socket *createSocket(int domain, int type, int protocol);
void initSocketList();
void listAdd(struct socket *newSocket);\

#endif //ANPNETSTACK_SOCKET_H