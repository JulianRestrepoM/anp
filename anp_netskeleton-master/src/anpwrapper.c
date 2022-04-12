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

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
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
    if (is_socket_supported(domain, type, protocol)) {
        //TODO: implement your logic here
        struct socket *newSocket = createSocket(domain, type, protocol);
        return newSocket->fd;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd){
        //TODO: implement your logic here

        if(connectionHead.connectionListHead == NULL) {
            initConnectionList();
        }

        struct sockaddr_in *sin = (struct sockaddr_in *) addr;
        struct socket *currSocket = getSocketByFd(sockfd);
        if (currSocket == NULL) {
            printf("error: Socket not found\n");
            return -1;
        }
        currSocket->dstaddr = ntohl((uint32_t) sin->sin_addr.s_addr);
        currSocket->dstaddrlen = addrlen;
        currSocket->srcport = SRC_PORT;
        currSocket->srcaddr = SRC_ADDR;
        memcpy(&currSocket->dstport, &sin->sin_port, sizeof(sin->sin_port));

        struct connection *newConnection = allocConnection();
        addNewConnection(newConnection, currSocket);

        if (doTcpHandshake(newConnection) != 0) {
            printf("Handshake failed\n");
            return -1;
        }


        return 0;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here

        printf("send called for len %zu\n", len);
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            printf("error: Socket not found\n");
        }
        if (getState(connection) != ESTABLISHED) {
            printf("error: connection not in ESTABLISHED state\n");
            return -1;
        }
        return sendTcpData(connection, buf, len);
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        printf("recv called clientside\n");
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            printf("error: Socket not found\n");
        }
        if (getState(connection) != ESTABLISHED) {
            printf("error: connection not in ESTABLISHED state\n");
            return -1;
        }
        setReadyToRecv(connection, true);
        int ret = getData(connection, buf, len);
        setReadyToRecv(connection, false);
        return ret;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        printf("CLOSSSINGGGG\n");
        struct connection *toClose = findConnectionByFd(sockfd);
        struct socket *sock = toClose->sock;
        int ret = doTcpClose(toClose);
        sockListRemove(sock);
        connectionListRemove(toClose);

        free(toClose);
        return ret;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}
