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
static int (*_fcntl)(int fd, int cmd, ...) = NULL;
static int (*_getpeername)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;
static ssize_t (*_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*_read)(int fd, void *buf, size_t count) = NULL;
static int (*_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) = NULL;
static int (*_getsockname)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;
static int (*_poll)(struct pollfd *fds, nfds_t nfds, int timeout) = NULL;
static int (*_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_listen)(int sockfds, int backlog) = NULL;
static int (*_accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM) && !(type & SOCK_DGRAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
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
        return newSocket->fd;
        }
        if(type & SOCK_DGRAM) {
            printf("ANP UDP SOCKET\n");
        }
        // int sock = _socket(domain, type, protocol);
        // printf("TCP SOCK %d\n", sock);
        // return sock;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    printf("CLIENT CALLED: connect: sockfd=%d\n", sockfd);
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

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;

        if (currSocket == NULL)
        {
            printf("error: Socket not found\n");
            return -1;
        }
        currSocket->dstaddr = ntohl((uint32_t)sin->sin_addr.s_addr);
        currSocket->dstaddrlen = addrlen;
        currSocket->srcport = genRandomPort();
        // if(currSocket->srcaddr == 0) {
            currSocket->srcaddr = SRC_ADDR;
        // }
        
        memcpy(&currSocket->dstport, &sin->sin_port, sizeof(sin->sin_port));
        // currSocket->dstport = sin->sin_port; //todo can i do this instead??

        struct connection *newConnection = allocConnection();
        addNewConnection(newConnection, currSocket);

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
            printf("UDP CONNECT\n");
            return 0;
        }
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    // printf("CLIENT CALLED: send: sockfd%d\n", sockfd);
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
            if (getState(connection) != ESTABLISHED) {
                printf("error: connection not in ESTABLISHED state\n");
                return -1;
            }
            return sendTcpData(connection, buf, len);
        }
        else if(connection->sock->type & SOCK_DGRAM) {
            return sendUdpData(connection, buf, len);
        }
        
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    // printf("CLIENT CALLED: recv: sockfd%d, len=%d\n", sockfd, len);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        // printf("recv called clientside\n");
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
            int ret = getData(connection, buf, len);
            // printf("RECEIVED = %d\n", ret);
            setReadyToRecv(connection, false);
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
        struct socket *sock = toClose->sock;
        if(sock->type == SOCK_STREAM) {
            ret = doTcpClose(toClose);
        }
        sockListRemove(sock);
        connectionListRemove(toClose);

        free(toClose);
        return ret;
    }
    // the default path
    return _close(sockfd);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    printf("CLIENT CALLED: setsockopt; sockf=%d\n", sockfd);
    // if(isFdUsed(sockfd)) {
    //     // printf("HELLO???\n");
    //     return 0;
    // }
    // return _setsockopt(sockfd, level, optname, optval, optlen);
    return 0;
}

int getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen) {
    printf("CLIENT CALLED: getsockopt; sockf=%d\n", sockfd);
    // printf("OPTLEN = %02x, Optval =%p\n", (uint8_t*)optlen[0], optval);
    if(isFdUsed(sockfd)) {
        // if(level == 6) {
        //     optval = 1;
        //     *optlen = 4;
        //     return 0;
        // }
        // if(level == 1) {
        //     // struct socket *currSocket = getSocketByFd(sockfd);
        //     // optval = (void *restrict) 113;
        //     // optval = 113;
        //     // *optlen =  sizeof(optval);
        //     // printf("OPTlen = %02x, OPTval =%p\n", (uint8_t*)optlen[0], optval);
        //     return 0;
         // }
        // optval = 1072;
        // optlen = sizeof(1072);
        return 0;
    }
    // int result = _getsockopt(sockfd, level, optname, optval, optlen);
    // // optval = 113;
    // // optlen[0]= 1214141;
    // // printf("OPTlen = %02x, OPTval =%p\n", (uint8_t*)optlen[0], optval);
    // return _getsockopt(sockfd, level, optname, optval, optlen);
    // return result;
    return 0;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    printf("CLIENT CALLED: sendto; fd=%d\n", sockfd);
    return _sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    printf("CLIENT CALLED: recvfrom; fd=%d\n", sockfd);
    return _recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

int fcntl(int fd, int cmd, ...) {
    printf("CLIENT CALLED: fcntl; fd=%d, command=%d\n", fd, cmd);
    if(isFdUsed(fd)) {
        return 0;
    }
    return _fcntl(fd, cmd);
}

int getpeername (int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: getpeername; sock=%d\n", sockfd);
    // if(isFdUsed(sockfd)) {
    //     struct socket *currsock = getSocketByFd(sockfd);
    //     if(addrlen < currsock->dstaddrlen) {
    //         printf("peer address too small");
    //     }
    //     // addr = currsock->dstaddr;
    //     return 0;
    // }
    // int theAddr[16];
    // printf("OLD PEER = ");
    // for(int i = 0; i <16; i++) {
    //     theAddr[i] = addr->sa_data[i];
    //     printf("%d", theAddr[i]);
    //     i++;
    // }
    // printf("\n");
    // return _getpeername(sockfd, addr, addrlen);
    return 0;
}

int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: getsockname; sockfd%d\n", sockfd);
    // if(isFdUsed(sockfd)) {

    //     struct socket *currsock = getSocketByFd(sockfd);
    //     if(*addrlen < currsock->srcaddrlen) {
    //         printf("sockname address too small");
    //         // memcpy(&addrlen, &currsock->srcaddrlen, sizeof(currsock->srcaddrlen));
    //         addrlen = currsock->srcaddrlen; 
    //     }
    //     uint32_t *netAddr = htonl(currsock->srcaddr);
    //     memcpy(&addr->sa_data, &netAddr, currsock->srcaddrlen);
    //     // sprintf(addr->sa_data, "%08x", currsock->srcaddr);

    //     return 0;
    // }
    // return _getsockname(sockfd, addr, addrlen);
    return 0;
}

ssize_t write(int fd, const void*buf, size_t count) {
    // printf("CLIENT CALLED: write; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        printf("ANP CLIENT CALLED: write; sock=%d, count=%d\n", fd, count);
        struct socket *sock = getSocketByFd(fd); 
        return send(fd, buf, count, 0);
    }
    return _write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    // printf("CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        printf("ANP CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
        return recv(fd, buf, count, 0);
    }
    return _read(fd, buf, count);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    // printf("CLIENT CALLED: select;\n ");
    // if(writefds != NULL && FD_ISSET(501,writefds)) {
    //     printf("ANP SELECT WRITE\n");
    //     return 1;
    // }
    // else if(readfds != NULL && FD_ISSET(501, readfds)) {
    //     printf("ANP SELECT READ\n");
    //     return 1;
    // }
    // if(nfds > ANP_SOCKET_MIN_VAL) {
    //     // printf("ANP SELECT\n");
    //     // sleep(0.1)
    //     if(readfds != NULL) {
    //         // printf("ANP SELECT READ\n");
    //         struct connection *connection = findConnectionByFd(sockHead.highestFd);
    //         if(!sub_queue_empty(connection->recvPkts)) {
    //             return 1;
    //         }
    //         if(sub_queue_empty(connection->recvPkts)) {
    //             printf("SELECT SLEEPING\n");
    //             usleep(timeout->tv_usec);
    //         } 
    //         if(sub_queue_empty(connection->recvPkts)) {
    //             return 0;
    //         }
    //     }
    //     printf("ANP SELECT WRITE\n");
    //     return 1;
    // }
    // int result = _select(nfds, readfds, writefds, exceptfds, timeout);
    // printf("SELECT RESULT %d\n", result);
    // return result;
    return 1;
    // return _select(nfds, readfds, writefds, exceptfds, timeout);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) { 
    printf("CLIENT CALLED: poll\n");

    // int result = _poll(fds, nfds, timeout);
    // printf("POLL Return %d\n", result);
    // return result;

    return _poll(fds, nfds, timeout);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    printf("CLIENT CALLED: bind; sock%d\n", sockfd);
    if(isFdUsed(sockfd)) {
        struct socket *sock = getSocketByFd(sockfd);
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sock->srcaddr = ((uint32_t)sin->sin_addr.s_addr); //TODO: maybe i need to use memcpy
        sock->srcaddrlen = addrlen;
        sock->srcport = ntohs(sin->sin_port);
        printf("BIND PORT %d\n", sock->srcport);
        char *ip = inet_ntoa(sin->sin_addr);
        printf("ADDRESS = %s\n", ip);
        return 0;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    char *ip = inet_ntoa(sin->sin_addr);
    printf("ADDRESS = %s\n", ip);
    return _bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    printf("CLIENT CALLED: listen; sock%d\n", sockfd);
    if(isFdUsed(sockfd)) { 
        struct socket *sock = getSocketByFd(sockfd);
        sock->backlog = backlog;
        sock->isPassive = true;
        return 0;
    }
    return _listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    printf("CLIENT CALLED: accept\n");
    if(isFdUsed(sockfd)) {
        struct socket *sock = getSocketByFd(sockfd);
        while(!sock->pendingC) {

        }
        return socket(sock->domain, sock->type, sock->protocol);
    }

    return _accept(sockfd, addr, addrlen);
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
    _fcntl = dlsym(RTLD_NEXT, "fcntl");
    _getpeername = dlsym(RTLD_NEXT, "getpeername");
    _write = dlsym(RTLD_NEXT, "write");
    _read = dlsym(RTLD_NEXT, "read");
    _select = dlsym(RTLD_NEXT, "select");
    _getsockname = dlsym(RTLD_NEXT, "getsockname");
   void *hndpoll = dlopen("libc.so.6",RTLD_LAZY);
    _poll = dlsym(hndpoll, "poll");
    _bind = dlsym(RTLD_NEXT, "bind");
    _listen = dlsym(RTLD_NEXT, "listen");
    _accept = dlsym(RTLD_NEXT, "accept");

}
