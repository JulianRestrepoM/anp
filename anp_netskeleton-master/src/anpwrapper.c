/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "socket.h"
#include "connection.h"
#include "tcp.h"
#include "udp.h"

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;
static int (*_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen) = NULL;
static int (*_getsockopt)(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen) = NULL;
static ssize_t (*_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static ssize_t (*_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) = NULL;
static int (*_getpeername)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;
static ssize_t (*_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*_read)(int fd, void *buf, size_t count) = NULL;
static int (*_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) = NULL;
static int (*_getsockname)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;
static int (*_poll)(struct pollfd *fds, nfds_t nfds, int timeout) = NULL;
static int (*_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_listen)(int sockfds, int backlog) = NULL;
static int (*_accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;
static int (*_fcntl64)(int fd, int cmd, ...) = NULL;
static int (*___poll)(struct pollfd *fds, nfds_t nfds, int timeout) = NULL;
static ssize_t (*_sendmsg)(int sockfd, const struct msghdr *msg, int flags) = NULL;
static int(*___sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM) && !(type & SOCK_DGRAM)) { //uncomment to support UDP
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    printf("CLIENT CALLED: socket: domain=%d, type=%d, protocol=%d\n", domain, type, protocol);
    if (is_socket_supported(domain, type, protocol)) {
        if((type & SOCK_STREAM) || (type & SOCK_DGRAM)) {
            // TODO: implement your logic here
        struct socket *newSocket = createSocket(domain, type, protocol);
        printf("ANP SOCKET %d\n", newSocket->fd);
        if(type & SOCK_DGRAM) {
            printf("ANP UDP SOCKET\n");
        }
        return newSocket->fd;
        }
        
        // int sock = _socket(domain, type, protocol);
        // printf("TCP SOCK %d\n", sock);
        // return sock;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    int sockid = _socket(domain, type, protocol);
    printf("SOCKET FD %d\n", sockid);
    return sockid;
    // return _socket(domain, type, protocol);
}

//alows bypassing handshake and acks of tcp. so basically udp in tcp format. used to test waitAck cost
int connectTest(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    // printf("CLIENT CALLED: connectTest: sockfd=%d\n", sockfd);
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if (is_anp_sockfd)
    {
        // TODO: implement your logic here
        struct socket *currSocket = getSocketByFd(sockfd);
        if (connectionHead.connectionListHead == NULL)
        {
            initConnectionList();
        }

        if (currSocket == NULL)
        {
            printf("error: Socket not found\n");
            return -1;
        }
        currSocket->dstaddrlen = addrlen;
        currSocket->srcport = genRandomPort();
        currSocket->srcaddr = SRC_ADDR;

        struct connection *newConnection = allocConnection();
        addNewConnection(newConnection, currSocket);

       return 0;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    printf("CLIENT CALLED: connect: sockfd=%d\n", sockfd);
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if (is_anp_sockfd)
    {
        // return connectTest(sockfd, addr, addrlen);
        // TODO: implement your logic here
        struct socket *currSocket = getSocketByFd(sockfd);
        if (connectionHead.connectionListHead == NULL)
        {
            initConnectionList();
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;

        if (currSocket == NULL)
        {
            printf("error: Socket not found\n");
            return -1;
        }
        currSocket->dstaddr = ntohl((uint32_t)sin->sin_addr.s_addr);
        printf("DSTADRESS = %ld\n", currSocket->dstaddr);
        currSocket->dstaddrlen = addrlen;
        currSocket->srcport = genRandomPort();
        // if(currSocket->srcaddr == 0) {
            currSocket->srcaddr = SRC_ADDR;
        // }

        // printf("SING PORT  %d lenght %d\n", sin->sin_addr);
        
        memcpy(&currSocket->dstport, &sin->sin_port, sizeof(sin->sin_port));
        printf("DESTINATION PORT = %d\n", currSocket->dstport);
        printf("SOURCE PORT = %d\n", currSocket->srcport);
        // currSocket->dstport = sin->sin_port; //todo can i do this instead??

        struct connection *newConnection = allocConnection();
        addNewConnection(newConnection, currSocket);

        // struct connection *dstConnection = findConnectionbyPort(htons(currSocket->dstport)); //TODO: risk assuming dstconnection is local. what if server is reused without ouside connection??
        // struct connection *currConnection = findConnectionByFd(sockfd);
        struct socket *dstSock = getSocketByPort(htons(currSocket->dstport));

        if(dstSock) {
            printf("ITS LOCAL connecting to sock %d\n", dstSock->fd);
            // dstConnection->isLocalConnection == true; //might need to use locks for this
            // currConnection->isLocalConnection == true;
            // setIsLocal(dstConnection, true);
            setIsLocal(newConnection, true);
        }
        else {
            printf("ITS WIDE\n");
            // currConnection->isLocalConnection == false;
            setIsLocal(newConnection, false);
        }

        if (currSocket->type & SOCK_STREAM)
        {
            if (doTcpHandshake(newConnection) != 0)
            {
                printf("Handshake failed\n");
                return -1;
            }
            printf("connect sucess\n");
            return 0;
        }
        else {
            printf("UDP CONNECT sock %d\n", sockfd);
            return 0;
        }
    }
    // the default path
    // struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    // printf("CONNECT TO ADDRESS %ld\n", ntohl((uint32_t)sin->sin_addr.s_addr));
    return _connect(sockfd, addr, addrlen);
}


ssize_t sendTest(int sockfd, const void *buf, size_t len, int flags)
{
    // printf("CLIENT CALLED: sendTest: sockfd%d\n", sockfd);
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        

        // printf("send called for len %zu\n", len);
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            printf("error: Socket not found\n");
        }
        if(connection->sock->type & SOCK_STREAM) {
            return sendTcpDataTest(connection, buf, len);
        }
        
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}



// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    printf("CLIENT CALLED: send: sockfd%d\n", sockfd);
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        // printf("CALL AMOUNT = %d and sock %d\n", anpCallCounter, sockfd);
        
        // return sendTest(sockfd, buf, len, flags);
        // printf("send called for len %zu\n", len);
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            printf("error: Socket not found\n");
        }
        if(connection->sock->type & SOCK_STREAM) {
            if (getState(connection) != ESTABLISHED) {
                printf("error: connection not in ESTABLISHED state\n");
                return -1;
            }
            ssize_t result =sendTcpData(connection, buf, len);
            printf("sent %d\n", result);
            return result;
            // return sendTcpData(connection, buf, len)-54; //tcp segment size
        }
        else if(connection->sock->type & SOCK_DGRAM) {
            return sendUdpData(connection, buf, len);
        }
        
    }
    // the default path
    ssize_t result = _send(sockfd, buf, len, flags);
    printf("sent %d\n", result);
    return result;
    return _send(sockfd, buf, len, flags);
}



ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    printf("CLIENT CALLED: recv: sockfd%d, len=%d\n", sockfd, len);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        printf("CALL AMOUNT = %d and sock %d\n", len, sockfd);
        //TODO: implement your logic here
        // printf("recv called clientside NUMBER %d\n", anpCallCounter);
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            printf("error: Socket not found\n");
        }
        if (connection->sock->type & SOCK_STREAM)
        {
            if (getState(connection) != ESTABLISHED)
            {
                printf("error: connection not in ESTABLISHED state\n");
                return -1;
            }
            setReadyToRecv(connection, true);
            printf("made 1\n");
            int ret = getData(connection, buf, len);
            printf("made 2\n");
            // printf("RECEIVED = %d\n", ret);
            setReadyToRecv(connection, false);
            printf("RECEVED TOTAL %d\n", ret);
            return ret;
        }
        else if(connection->sock->type & SOCK_DGRAM) {
            return 0;
        }
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    printf("CLIENT CALLED: close: sockf=%d\n", sockfd);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        int ret = 0;
        struct connection *toClose = findConnectionByFd(sockfd);
        if(!toClose) {
            struct socket *serverSocket = getSocketByFd(sockfd);
            if(serverSocket) {
                sockListRemove(serverSocket);
                return 0;
            }
        }
        struct socket *sock = toClose->sock;
        if(sock->type == SOCK_STREAM) {
            ret = doTcpClose(toClose);
        }
        sockListRemove(sock);
        connectionListRemove(toClose);

        free(toClose);
        printf("CLOSED SUCCESS %d result %d\n", sockfd, ret);
        return ret;
    }
    // the default path
    return _close(sockfd);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    printf("CLIENT CALLED: setsockopt; sockf=%d\n", sockfd);
    if(isFdUsed(sockfd)) {
        // printf("HELLO???\n");
        return 0;
    }
    return _setsockopt(sockfd, level, optname, optval, optlen);
    // return 0;
}

int getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen) {
    printf("CLIENT CALLED: getsockopt; sockf=%d level %d optname %d\n", sockfd, level, optname);

    if(isFdUsed(sockfd)) {
        // *optlen = 4;
        // int *optvalResult = (int*)optval;
        // optvalResult = 0;
        // optval = optvalResult;
        return 0;

    }
    return _getsockopt(sockfd, level, optname, optval, optlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    printf("CLIENT CALLED: sendto; fd=%d\n", sockfd);
    return _sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    printf("CLIENT CALLED: recvfrom; fd=%d wants %d\n", sockfd, len);
    // char fake[len];
    // ssize_t result = _recvfrom(sockfd, fake, len, flags, src_addr, addrlen);
    // for(int i = 0; i <=result; i++) {
    //     printf("%c", fake[i]);
    // }
    // printf("\n");
    // memset(fake, 0, len);
    // memcpy(buf, fake, len);

    // // ssize_t result = _recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    // // printf("THE RESULT IT RECVD %d\n", result);
    // return result;
    return _recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}


int getpeername (int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: getpeername; sock=%d\n", sockfd);
    if(isFdUsed(sockfd)) {
         struct socket *currsock = getSocketByFd(sockfd);
        if(*addrlen < sizeof(currsock->srcaddrlen)) {
            printf("sockname address too small\n");
            // memcpy(&addrlen, &currsock->srcaddrlen, sizeof(currsock->srcaddrlen));
            addrlen = currsock->srcaddrlen; 
            uint16_t *portAddr = (currsock->srcaddr);
            memcpy(&addr->sa_data, &portAddr, addrlen);
            printf("lieves\n");
            return 0;
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char *ip = inet_ntoa(sin->sin_addr);
        printf("getperrname BEFORE = %s and PORT = %d %d\n", ip, sin->sin_port, sin->sin_family);
        

        // uint32_t *portAddr = 0x7fff0000;
        // memcpy(&addr->sa_data, &portAddr, sizeof(currsock->srcaddr));
        // addrlen = sizeof(portAddr);

        sin->sin_port = currsock->dstport;
        sin->sin_addr.s_addr = htonl(0x7f000001); //TODO: get this value dynamically
        sin->sin_family = currsock->domain;
        // memcpy(&addr,&sin, sizeof(sin));
        struct sockaddr *returnVal = (struct sockaddr *)sin;
        memcpy(&addr,&returnVal, sizeof(returnVal));

        addrlen = (socklen_t)sizeof(returnVal);
        // struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        // char *ip = inet_ntoa(sin->sin_addr);
        // printf("getpeername Result = %s\n", ip);

        sin = (struct sockaddr_in *)addr;
        ip = inet_ntoa(sin->sin_addr);
        printf("getpeername  AFTER = %s %d %d\n", ip, sin->sin_port, sin->sin_family);
        
        return 0;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char *ip = inet_ntoa(sin->sin_addr);
    printf("getpeername = %s %d %d\n", ip, sin->sin_port, sin->sin_family);

    int result = _getpeername(sockfd, addr, addrlen);

    sin = (struct sockaddr_in *)addr;
    ip = inet_ntoa(sin->sin_addr);
    printf("getpeername AFTER = %s %d %d\n", ip, sin->sin_port, sin->sin_family);
    
    return result;
    // return _getpeername(sockfd, addr, addrlen);
    return 0;
}

int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: getsockname; sockfd%d\n", sockfd);
    if(isFdUsed(sockfd)) {

        struct socket *currsock = getSocketByFd(sockfd);
        if(*addrlen < sizeof(currsock->srcport)) {
            printf("sockname address too small\n");
            // memcpy(&addrlen, &currsock->srcaddrlen, sizeof(currsock->srcaddrlen));
            addrlen = currsock->srcaddrlen; 
            uint16_t *portAddr = (currsock->srcport);
            memcpy(&addr->sa_data, &portAddr, addrlen);
            printf("lieves\n");
            return 0;
        }
        // uint32_t *netAddr = (currsock->srcaddr);
        // memcpy(&addr->sa_data, &netAddr, currsock->srcaddrlen);
        // addrlen = currsock->srcaddrlen;
        // sprintf(addr->sa_data, "%08x", currsock->srcaddr);

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char *ip = inet_ntoa(sin->sin_addr);
        printf("ADDRESS BEFORE = %s %d %d\n", ip, sin->sin_port, sin->sin_family);

        // uint16_t *portAddr = (currsock->srcport);
        // memcpy(&addr->sa_data, &portAddr, sizeof(currsock->srcport));
        // addrlen = sizeof(portAddr);
        // printf("getSOckNAme %d\n", portAddr);

        sin->sin_port = currsock->srcport;
        sin->sin_addr.s_addr = htonl(0x7f000001);
        sin->sin_family = currsock->domain;
        struct sockaddr *returnVal = (struct sockaddr *)sin;
        memcpy(&addr,&returnVal, sizeof(returnVal));

        sin = (struct sockaddr_in *)addr;
        ip = inet_ntoa(sin->sin_addr);
        printf("getsockname AFter = %s %d %d\n", ip, sin->sin_port, sin->sin_family);

        return 0;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char *ip = inet_ntoa(sin->sin_addr);
    printf("getsockname = %s %d %d\n", ip, sin->sin_port, sin->sin_family);

    int result = _getsockname(sockfd, addr, addrlen);
 
    sin = (struct sockaddr_in *)addr;
    ip = inet_ntoa(sin->sin_addr);
    printf("getsockname AFTER = %s %d %d\n", ip, sin->sin_port, sin->sin_family);
    

    return result;

    return _getsockname(sockfd, addr, addrlen);
    
}

ssize_t write(int fd, const void*buf, size_t count) {
    // printf("CLIENT CALLED: write; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        printf("ANP CLIENT CALLED: write; sock=%d, count=%u\n", fd, count);
        struct socket *sock = getSocketByFd(fd); 

        // ssize_t result = send(fd, buf, count, 0);
        // printf("RESULTED %d\n", result);
        // return result;
        return send(fd, buf, count, 0);
    }
    return _write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    // printf("CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        printf("ANP CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
        // printf("ANP READ NUMBER: %d\n", anpCallCounter);
        return recv(fd, buf, count, 0);
    }
    return _read(fd, buf, count);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    printf("CLIENT CALLED: select;\n ");
    if(nfds > ANP_SOCKET_MIN_VAL) {
        if(readfds != NULL) {
            // printf("ANP SELECT READ\n");
            struct socket *sock = getSocketByFd(sockHead.highestFd);
            if(busyWaitingSub(sock->recvPkts, timeout->tv_sec)) {
                return 1;
            }
            return 0;
        }
        printf("ANP SELECT WRITE\n");
        return 1;
    }
    return _select(nfds, readfds, writefds, exceptfds, timeout);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) { 
    int fd = fds->fd;
    printf("CLIENT CALLED: poll %d timout %d\n", fd, timeout);
    if(isFdUsed(fd)) {
        int pollEvent = fds->events;
        printf("POLL EVENT %d \n", pollEvent);
        if(pollEvent == 4) { //POLLOUT
            fds->revents = 4;
            return 1;
        }
        else if(pollEvent == 262) { // POLLWRBAND | POLLRDNORM | POLLNVAL | POLLPRI according to bit mask
            struct socket *sock = getSocketByFd(fd);
            // if(!sub_queue_empty(connection->recvPkts)) {
            //     printf("THIS ONE 1\n");
            //     fds->revents = 260;
            //     return 1;
            // }
            // fds->revents = 200; //curl doesnt like this. 
            fds->revents = 260;
            return 1;
        }
        else if(pollEvent == 1) { //POLLIN
            struct socket *sock = getSocketByFd(fd);
            if(sock == NULL) {
                printf("POLL TIMED OUT 1\n");
                return 0;
            }
            if(sock->pendingC) {
                fds->revents = 1;
                return 1;
            }
            if(busyWaitingSub(sock->recvPkts, timeout)) {
                fds->revents = 1;
                return 1;
            }
            printf("POLL TIMED OUT 2\n");
            return 0;
        }
        else if(pollEvent == 195) { //POLLWRNORM | POLLRDBAND | POLLHUP | POLLOUT | POLLIN
            struct socket *sock = getSocketByFd(fd);
            if(sock == NULL) {
                printf("POLL TIMED OUT 3\n");
                return 0;
            }
            if(busyWaitingSub(sock->recvPkts, timeout)) {
                printf("THIS ONE 2\n");
                fds->revents = 65;
                return 1;
            }
            printf("POLL TIMED OUT 4\n");
            return 0;
        }
        printf("POLL TIMED OUT 5\n");
        return 0;
    } 

    return _poll(fds, nfds, timeout);
}

int __poll(struct pollfd *fds, nfds_t nfds, int timeout) { //wget
    printf("CLIENT CALLED: __poll\n");
    int fd = fds->fd;
    if(isFdUsed(fd)) {
        return poll(fds, nfds, timeout);
    }
    return ___poll(fds, nfds, timeout);
    
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    printf("CLIENT CALLED: bind; sock%d\n", sockfd);
    if(isFdUsed(sockfd)) {
        struct socket *sock = getSocketByFd(sockfd);
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sock->srcaddr = ((uint32_t)sin->sin_addr.s_addr); //TODO: maybe i need to use memcpy
        sock->srcaddrlen = addrlen;
        // sock->srcport = ntohs(sin->sin_port);
        sock->srcport = genRandomPort();
        printf("BIND PORT %d\n", sock->srcport);
        char *ip = inet_ntoa(sin->sin_addr);
        printf("ADDRESS = %s\n", ip);

        // //create a connection struct for the server
        // if (connectionHead.connectionListHead == NULL) 
        // {
        //     initConnectionList();
        // }
        // struct connection *newConnection = allocConnection();
        // addNewConnection(newConnection, sock);

        return 0;
    }
    // struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    // char *ip = inet_ntoa(sin->sin_addr);
    // printf("ADDRESS = %s\n", ip);
    return _bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    printf("CLIENT CALLED: listen; sock%d, backlog %d\n", sockfd, backlog);
    if(isFdUsed(sockfd)) { 
        // ++anpCallCounter;
        // struct connection *connection = findConnectionByFd(sockfd);
        // connection->sock->backlog = backlog;
        // connection->sock->isPassive = true;
        // setState(connection, LISTEN);
        struct socket *sock = getSocketByFd(sockfd);
        sock->backlog = backlog;
        sock->isPassive = true;
        return 0;
    }
    return _listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: accept sock %d\n", sockfd);
    if(isFdUsed(sockfd)) {
        struct socket *sock = getSocketByFd(sockfd);
        while(!sock->pendingC) {

        }
        int returnSocket = sock->pendingC->sock->fd;
        sock->pendingC = NULL;
        return returnSocket;
    }

    return _accept(sockfd, addr, addrlen);
}

int fcntl64(int fd, int cmd, ...) {
    printf("CLIENT CALLED: fcntl socket %d CMD = %d\n", fd, cmd);
    if(isFdUsed(fd)) {
        // printf("FCNTL HACKED %d\n", cmd);
        struct socket *sock = getSocketByFd(fd);

        if(cmd == 3) { //F_GETFL 
            if(sock->isNonBlocking) {
                return 2048;
            }
            return 0;
        }
        else if(cmd == 4) { //F_SETFL
            va_list args;
            va_start(args, cmd);
            int flagValue = va_arg(args, int);

            printf("FCNTL SET %d\n", flagValue);
            printf("SOCK %d is noW NON blOCKING\n", fd);
            
            sock->isNonBlocking = true;

        }
        return 0;
    }

    printf("FCNTL NOT HACKED\n");
    va_list args;
    va_start(args, cmd);
    int result = 0;
    if(cmd == 4) {
        int flagValue = va_arg(args, int);
        result = _fcntl64(fd, cmd, flagValue);
    }
    else {
        result = _fcntl64(fd, cmd, args);
    }
    // va_end(args);
    // printf("FCNTL RESULT %d %s\n", result, strerror(errno));
    return result;
    return 0;
    
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    printf("CLIENT CALLED: sendmsg %d\n", sockfd);
    return _sendmsg(sockfd, msg, flags);
}

int __sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    printf("CLIENT CALLED: sendmmsg (Multiple) %d falgs %d\n", sockfd, flags);
    if(isFdUsed(sockfd)) {   
        printf("vlen = %d\n", vlen);
        for(int i = 0; i < vlen; i++) {
            if(msgvec->msg_hdr.msg_iovlen > 1) {
                printf("OH OH, I need to implement it\n");
                sleep(5);
                return -1;
            }
            msgvec->msg_len = send(sockfd, msgvec->msg_hdr.msg_iov->iov_base, msgvec->msg_hdr.msg_iov->iov_len, 0)-42;
            // printf("NAME MESSAGE = %ld\n", msgvec->msg_hdr.msg_control);
            msgvec++;
        }
        // printf("sendmsg total = %d\n", sendResult);
        return vlen;
        // return send(sockfd, msgvec->msg_hdr.msg_iov, msgvec->msg_hdr.msg_iov->iov_len, 0);


        
    }
    int result = ___sendmmsg(sockfd, msgvec, vlen, flags);
    printf("sendmmsg result = %d and %ld\n", result, msgvec->msg_len);
    return result;
    // return ___sendmmsg(sockfd, msgvec, vlen, flags);
}


void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
    _setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    _getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    _sendto = dlsym(RTLD_NEXT, "sendto");
    _recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    _getpeername = dlsym(RTLD_NEXT, "getpeername");
    _write = dlsym(RTLD_NEXT, "write");
    _read = dlsym(RTLD_NEXT, "read");
    _select = dlsym(RTLD_NEXT, "select");
    _getsockname = dlsym(RTLD_NEXT, "getsockname");
   void *hndpoll = dlopen("libc.so.6",RTLD_LAZY);
    _poll = dlsym(hndpoll, "poll");
    ___poll = dlsym(RTLD_NEXT, "__poll");
    _bind = dlsym(RTLD_NEXT, "bind");
    _listen = dlsym(RTLD_NEXT, "listen");
    _accept = dlsym(RTLD_NEXT, "accept");
    _fcntl64 = dlsym(RTLD_NEXT, "fcntl64");
    _sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    ___sendmmsg = dlsym(RTLD_NEXT, "__sendmmsg");
}
