#ifndef ANPNETSTACK_SOCKET_H
#define ANPNETSTACK_SOCKET_H
#include "linklist.h"
#include "systems_headers.h"

#define ANP_SOCKET_MIN_VAL 500


struct socket {
    struct list_head list;
    int type;
    int domain;
    int protocol;
    int fd;
    int backlog;
    bool isPassive;
    bool pendingC;
    uint32_t srcaddr;
    uint32_t dstaddr;
    socklen_t dstaddrlen;
    socklen_t srcaddrlen;
    uint16_t dstport;
    uint16_t srcport;

};

typedef struct SOCKET_HEAD {
    int highestFd;
    struct list_head *listHead;
} socket_head;

socket_head sockHead;

struct socket *createSocket(int domain, int type, int protocol);
void initSocketList();
void sockListAdd(struct socket *newSocket);
void sockListRemove(struct socket *toDelete);
bool isFdUsed(int fd);
struct socket *getSocketByFd(int fd);
struct socket* allocSock();

#endif //ANPNETSTACK_SOCKET_H