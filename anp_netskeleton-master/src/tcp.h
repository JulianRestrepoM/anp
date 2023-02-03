#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#include "systems_headers.h"
#include "socket.h"
#include "ip.h"
#include "utilities.h"
#include "connection.h"
#include "config.h"

#define WIN_SIZE 1460 //the code doesnt like it when it gets packets larger. I think its cause it overwrites some packets


struct tcpHdr {
    uint16_t tcpSource;
    uint16_t tcpDest;
    uint32_t tcpSeqNum;
    uint32_t tcpAckNum;
    uint8_t tcpResPad1:4,
            tcpLen:4,
            tcpFin:1,
            tcpSyn:1,
            tcpRst:1,
            tcpPsh:1,
            tcpAck:1,
            tcpUrg:1,
            tcpResPad2:2;
    uint16_t tcpWinSize;
    uint16_t tcpChecksum;
    uint16_t tcpUrgentPointer;
    uint8_t tcpData[];
} __attribute__((packed));

struct tcpHdrwOptions {
    uint16_t tcpSource;
    uint16_t tcpDest;
    uint32_t tcpSeqNum;
    uint32_t tcpAckNum;
    uint8_t tcpResPad1:4,
            tcpLen:4,
            tcpFin:1,
            tcpSyn:1,
            tcpRst:1,
            tcpPsh:1,
            tcpAck:1,
            tcpUrg:1,
            tcpResPad2:2;
    uint16_t tcpWinSize;
    uint16_t tcpChecksum;
    uint16_t tcpUrgentPointer;
    uint8_t kind;
    uint8_t length;
    uint16_t mss;
    uint8_t tcpData[];
    
} __attribute__((packed));

struct tcpHdr *tcpHdrFromSub(struct subuff *sub);
int sendSyn(struct connection *connection);
int sendSynAck(struct connection *connection);
struct subuff *allocTcpSub(int dataLen);
struct subuff *allocTcpSubwOptions(int dataLen);
struct subuff *makeSynSub(struct connection *connection);
struct subuff *makeSynAckSub(struct connection *connection);
void setSynOptionsTcpHdr(struct subuff *sub, struct connection *connection);
void setSynAckOptionsTcpHdr(struct subuff *sub, struct connection *connection);
int doTcpHandshake(struct connection *connection);
void setGeneralOptionsTcpHdr(struct tcpHdr *hdr, struct connection *connection, uint32_t seqNum, uint32_t ackNum);
void setAckOptionsTcpHdr(struct subuff *sub, struct connection *connection, uint32_t ackNum);
int tcpRx(struct subuff *sub);
int handleSynAck(struct subuff *sub);
int handleAck(struct subuff *sub);
int handleSyn(struct subuff *sub);
int sendAck(struct connection *connection, uint32_t ackNum);
struct subuff *makeAckSub(struct connection *connection, uint32_t ackNum);
int sendTcpData(struct connection *connection, const void *buf, size_t len);
int getData(struct connection *connection, void *buf, size_t len);
int handleRecv(struct connection *incomingConnection, struct subuff *sub, struct tcpHdr *hdr);
int doTcpClose(struct connection *connection);
struct subuff *makeFinSub(struct connection *connection);
int sendFin(struct connection *connection);
int waitForAck(struct connection *connection);
int handleFinAck(struct subuff *sub);

#define TCP_HDR_LEN sizeof(struct tcpHdr)
#define TCP_HDRwOptions_LEN sizeof(struct tcpHdrwOptions)


#endif //ANPNETSTACK_TCP_H