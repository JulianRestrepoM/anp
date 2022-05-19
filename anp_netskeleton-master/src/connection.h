#ifndef ANPNETSTACK_CONNECTION_H
#define ANPNETSTACK_CONNECTION_H
#include "systems_headers.h"
#include "linklist.h"
#include "socket.h"
#include "subuff.h"

#define CLOSED 0
#define SYN_SENT 1
#define ESTABLISHED 2
#define FIN_WAIT_1 3
#define FIN_WAIT_2 4
#define TIME_WAIT 5
#define CLOSE_WAIT 6 //TODO: probably have to set the proper states when server initiantes CLosing
#define LAST_ACK 7


struct connection {
    pthread_mutex_t connectionLock;
    pthread_cond_t synackRecv;
    pthread_cond_t ackRecv;
    pthread_cond_t finAckRecv;
    bool waitingForAck;
    bool readyToRecv;
    struct subuff_head *recvPkts;
    struct list_head list;
    int tcpState;
    struct socket *sock;
    uint32_t seqNum;
    int packetNum;
    uint32_t lastRecvSeq;

};

struct connection_head {
    struct list_head *connectionListHead;
    int len;
} connectionHead;

void initConnectionList();
struct connection* allocConnection();
void connectionListAdd(struct connection *newConnection);
void connectionListRemove(struct connection *newConnection);
struct connection* findConnectionBySeqNum(uint32_t num);
struct connection* findConnectionByFd(int fd);
void addNewConnection(struct connection *newConnection, struct socket *sock);
int setState(struct connection *connection, int state);
int getState(struct connection *connection);
int setWaitingForAck(struct connection *connection, bool waiting);
int getWaitingForAck(struct connection *connection);
int setReadyToRecv(struct connection *connection, bool ready);
uint32_t getSeqNum(struct connection *connection);
uint32_t setSeqNum(struct connection *connection, uint32_t newSeq);
uint32_t getLastRecvSeq(struct connection *connection);
uint32_t setLastRecvSeqNum(struct connection *connection, uint32_t newSeq);




#endif //ANPNETSTACK_CONNECTION_H