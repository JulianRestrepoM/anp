#include "connection.h"

void initConnectionList() {
    connectionHead.connectionListHead = (struct list_head *) malloc(sizeof(struct list_head));
    connectionHead.len = 0;
    list_init(connectionHead.connectionListHead);
}

struct connection* allocConnection() {
    struct connection *newConnection = (struct connection *) malloc(sizeof(struct connection));
    newConnection->recvPkts = (struct subuff_head *) malloc(sizeof(struct subuff_head));
    return newConnection;
}

struct connection* findConnectionbyPort(uint16_t port)  {
    struct list_head *item;
    struct connection *entry;
    list_for_each(item, connectionHead.connectionListHead) {
        entry = list_entry(item, struct connection, list);
        pthread_mutex_lock(&entry->connectionLock);
        if (entry->sock->srcport == ntohs(port)) {
            pthread_mutex_unlock(&entry->connectionLock);
            return entry;
        }
        pthread_mutex_unlock(&entry->connectionLock);
    }
    return NULL;
}

struct connection* findConnectionByFd(int fd) {
    struct list_head *item;
    struct connection *entry;
    list_for_each(item, connectionHead.connectionListHead) {
        entry = list_entry(item, struct connection, list);
        pthread_mutex_lock(&entry->connectionLock);
        if (entry->sock->fd == fd) {
            pthread_mutex_unlock(&entry->connectionLock);
            return entry;
        }
        pthread_mutex_unlock(&entry->connectionLock);
    }
    return NULL;
}

void connectionListAdd(struct connection *newConnection) {
    list_add(&newConnection->list, connectionHead.connectionListHead);
    connectionHead.len++;
}

void connectionListRemove(struct connection *newConnection) {
    list_del(&newConnection->list);
    connectionHead.len--;
}

struct connection* findConnectionBySeqNum(uint32_t num) {
    struct list_head *item;
    struct connection *entry;
    list_for_each(item, connectionHead.connectionListHead) {
        entry = list_entry(item, struct connection, list);
        pthread_mutex_lock(&entry->connectionLock);
        if(entry->seqNum == num) {
            pthread_mutex_unlock(&entry->connectionLock);
            return entry;
        }
        pthread_mutex_unlock(&entry->connectionLock);
    }
    return NULL;
}

void addNewConnection(struct connection *newConnection, struct socket *sock) {
    pthread_mutex_init(&newConnection->connectionLock, NULL);
    pthread_cond_init(&newConnection->synackRecv, NULL);
    pthread_cond_init(&newConnection->ackRecv, NULL);
    pthread_cond_init(&newConnection->finAckRecv, NULL);

    pthread_mutex_lock(&newConnection->connectionLock);

    newConnection->sock = sock;
    newConnection->seqNum = rand() % UINT32_MAX;
    newConnection->tcpState = CLOSED;
    newConnection->readyToRecv = false;
    newConnection->waitingForAck = false;

    sub_queue_init(newConnection->recvPkts);

    pthread_mutex_unlock(&newConnection->connectionLock);
    connectionListAdd(newConnection);
}

int setState(struct connection *connection, int state) {
    pthread_mutex_lock(&connection->connectionLock);
    connection->tcpState = state;
    pthread_mutex_unlock(&connection->connectionLock);
}

int getState(struct connection *connection) {
    int currState;
    pthread_mutex_lock(&connection->connectionLock);
    currState = connection->tcpState;
    pthread_mutex_unlock(&connection->connectionLock);
    return currState;
}

int setWaitingForAck(struct connection*connection, bool waiting) {
    pthread_mutex_lock(&connection->connectionLock);
    connection->waitingForAck = waiting;
    pthread_mutex_unlock(&connection->connectionLock);
}

int getWaitingForAck(struct connection *connection) {
    bool currState;
    pthread_mutex_lock(&connection->connectionLock);
    currState = connection->waitingForAck;
    pthread_mutex_unlock(&connection->connectionLock);
    return currState;
}

int setReadyToRecv(struct connection *connection, bool ready) {
    pthread_mutex_lock(&connection->connectionLock);
    connection->readyToRecv = ready;
    pthread_mutex_unlock(&connection->connectionLock);
}

int GetReadyToRecv(struct connection *connection) {
    bool currState;
    pthread_mutex_lock(&connection->connectionLock);
    currState = connection->readyToRecv;
    pthread_mutex_unlock(&connection->connectionLock);
    return currState;
}

uint32_t getSeqNum(struct connection *connection) {
    uint32_t currSeq;
    pthread_mutex_lock(&connection->connectionLock);
    currSeq = connection->seqNum;
    pthread_mutex_unlock(&connection->connectionLock);
    return currSeq;
}

uint32_t setSeqNum(struct connection *connection, uint32_t newSeq) {
    pthread_mutex_lock(&connection->connectionLock);
    connection->seqNum = newSeq;
    pthread_mutex_unlock(&connection->connectionLock);
}

uint32_t getLastRecvSeq(struct connection *connection) {
    uint32_t lastSeq;
    pthread_mutex_lock(&connection->connectionLock);
    lastSeq = connection->lastRecvSeq;
    pthread_mutex_unlock(&connection->connectionLock);
    return lastSeq;
}

uint32_t setLastRecvSeqNum(struct connection *connection, uint32_t newSeq) {
    pthread_mutex_lock(&connection->connectionLock);
    connection->lastRecvSeq = newSeq;
    pthread_mutex_unlock(&connection->connectionLock);
}

int genRandomPort() {
    srand(time(0));
    int portNum = (rand()% PORT_RANGE);
    return portNum;
}