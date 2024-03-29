#ifndef ANPNETSTACK_SOCKET_H
#define ANPNETSTACK_SOCKET_H
#include "linklist.h"
#include "systems_headers.h"
#include "subuff.h"

#define ANP_SOCKET_MIN_VAL 500


struct socket {
    pthread_mutex_t sock_lock;
    struct list_head list;
    int type;
    int domain;
    int protocol;
    int fd;
    int backlog;
    bool isNonBlocking;
    bool isPassive;
    int readAmount;
    struct connection *pendingC;
    uint32_t srcaddr;
    uint32_t dstaddr;
    socklen_t dstaddrlen;
    socklen_t srcaddrlen;
    uint16_t dstport;
    uint16_t srcport;
    struct subuff_head *recvPkts;

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
struct socket *getSocketByPort(int port);
struct socket* allocSock();

#endif //ANPNETSTACK_SOCKET_H