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
static int (*_fcntl)(int fd, int cmd, ...) = NULL;
static int (*___poll)(struct pollfd *fds, nfds_t nfds, int timeout) = NULL;
static ssize_t (*_sendmsg)(int sockfd, const struct msghdr *msg, int flags) = NULL;
static int (*___sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) = NULL;
static int (*_ioctl)(int fd, unsigned long request, ...) = NULL;
static int (*___close)(int sockfd) = NULL;

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
    // printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

int socket(int domain, int type, int protocol) {
    // printf("CLIENT CALLED: socket: domain=%d, type=%d, protocol=%d\n", domain, type, protocol);
    if (is_socket_supported(domain, type, protocol)) {
        if((type & SOCK_STREAM) || (type & SOCK_DGRAM)) {
        struct socket *newSocket = createSocket(domain, type, protocol);
        return newSocket->fd;
        }
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    // printf("CLIENT CALLED: connect: sockfd=%d\n", sockfd);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if (is_anp_sockfd)
    {
        struct socket *currSocket = getSocketByFd(sockfd);
        if (connectionHead.connectionListHead == NULL)
        {
            initConnectionList();
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;

        if (currSocket == NULL)
        {
            // printf("error: Socket not found\n");
            return -1;
        }
        currSocket->dstaddr = ntohl((uint32_t)sin->sin_addr.s_addr);
        currSocket->dstaddrlen = addrlen;
        currSocket->srcport = genRandomPort();
        currSocket->srcaddr = SRC_ADDR;

        
        memcpy(&currSocket->dstport, &sin->sin_port, sizeof(sin->sin_port));

        struct connection *newConnection = allocConnection();
        if(!newConnection) {
            // printf("its NULL\n");
            return -1;
        }
        addNewConnection(newConnection, currSocket);

        struct socket *dstSock = getSocketByPort(htons(currSocket->dstport));

        if(dstSock) {
            setIsLocal(newConnection, true);
        }
        else {
            setIsLocal(newConnection, false);
        }

        if (currSocket->type & SOCK_STREAM)
        {
            if (doTcpHandshake(newConnection) != 0)
            {
                // printf("Handshake failed\n");
                return -1;
            }
            return 0;
        }
        else {
            return 0;
        }
    }
    return _connect(sockfd, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags){
    // printf("CLIENT CALLED: send: sockfd%d len %d\n", sockfd, len);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            // printf("error: Socket not found\n");
        }
        if(connection->sock->type & SOCK_STREAM) {
            if (getState(connection) != ESTABLISHED) {
                // printf("error: connection not in ESTABLISHED state\n");
                return -1;
            }
            return sendTcpData(connection, buf, len);
        }
        else if(connection->sock->type & SOCK_DGRAM) {
            return sendUdpData(connection, buf, len);
        }
        
    }
    return _send(sockfd, buf, len, flags);
}



ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    // printf("CLIENT CALLED: recv: sockfd%d, len=%d\n", sockfd, len);
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        if(buf == NULL) {
            // printf("recv buf is null\n");
            errno = EINVAL;
            return -1;
        }
        struct connection *connection = findConnectionByFd(sockfd);
        if (connection == NULL) {
            // printf("error: Socket not found\n");
        }
        if (connection->sock->type & SOCK_STREAM)
        {
            setReadyToRecv(connection, true);
            int ret = getData(connection, buf, len);
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
    // printf("CLIENT CALLED: close: sockf=%d\n", sockfd); //speedtest doesnt like this print
    bool is_anp_sockfd = isFdUsed(sockfd);
    if(is_anp_sockfd) {
        // printf("CLIENT CALLED: close: sockf=%d\n", sockfd); 
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
        return ret;
    }
    // the default path
    return _close(sockfd);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    // printf("CLIENT CALLED: setsockopt; sockf=%d level %d optname %d\n", sockfd, level, optname);
    if(isFdUsed(sockfd)) {
        return 0;
    }
    return _setsockopt(sockfd, level, optname, optval, optlen);
}

int getsockopt(int sockfd, int level, int optname, void *restrict optval, socklen_t *restrict optlen) {
    // printf("CLIENT CALLED: getsockopt; sockf=%d level %d optname %d\n", sockfd, level, optname);
    if(isFdUsed(sockfd)) {
        if(level == SOL_SOCKET) {
            if(optname == SO_TYPE) {
                int *optvalResult = (int*)optval;
                *optvalResult = SOCK_STREAM;
                return 0;
            }
            else if(optname == SO_ERROR) {
                return 0;
            }
            else if(optname == SO_SNDBUF) {
                int *optvalResult = (int*)optval;
                *optvalResult = WIN_SIZE;
                return 0;
            }
            else if(optname == SO_RCVBUF) {
                int *optvalResult = (int*)optval;
                *optvalResult = WIN_SIZE;
                return 0;
            }
            else {
                printf("getsockopt unsupported optname\n");
                _getsockopt(sockfd, level, optname, optval, optlen);
                exit(-1);
            }
        }
        else if(level == 6) { // SOL_TCP
            if(optname == 2) { //TCP_MAXSEG
                int *optvalResult = (int*)optval;
                *optvalResult = MSS;
                return 0;
            }
        } 
        else{
            
            printf("getsockopt unsupported level\n");
            _getsockopt(sockfd, level, optname, optval, optlen);
            exit(-1);
        }
        return 0;
        //  exit(0);
    }
    return _getsockopt(sockfd, level, optname, optval, optlen);
    
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    // printf("CLIENT CALLED: sendto; fd=%d\n", sockfd);
    return _sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    // printf("CLIENT CALLED: recvfrom; fd=%d wants %d\n", sockfd, len);
    if(isFdUsed(sockfd)) {
        if(buf == NULL) {
            // printf("recvfrom buf is null\n");
            errno = EINVAL;
            return -1;
        }
        struct socket *sock = getSocketByFd(sockfd);
        return getUdpData(sock, buf, len, flags, src_addr, addrlen);
    }
    return _recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

}


int getpeername (int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    // printf("CLIENT CALLED: getpeername; sock=%d\n", sockfd);
    if(isFdUsed(sockfd)) {
         struct socket *currsock = getSocketByFd(sockfd);
        if(*addrlen < sizeof(currsock->srcaddrlen)) {
            addrlen = currsock->srcaddrlen; 
            uint16_t *portAddr = (currsock->srcaddr);
            memcpy(&addr->sa_data, &portAddr, addrlen);
            return 0;
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;        
        sin->sin_port = currsock->dstport;
        sin->sin_addr.s_addr = htonl(0x7f000001); //TODO: get this value dynamically
        sin->sin_family = currsock->domain;
        struct sockaddr *returnVal = (struct sockaddr *)sin;
        memcpy(&addr,&returnVal, sizeof(returnVal));

        addrlen = (socklen_t)sizeof(returnVal);      
        return 0;
    }
    return _getpeername(sockfd, addr, addrlen);
}

int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    // printf("CLIENT CALLED: getsockname; sockfd%d\n", sockfd);
    if(isFdUsed(sockfd)) {
        struct socket *currsock = getSocketByFd(sockfd);
        if(*addrlen < sizeof(currsock->srcport)) {
            addrlen = currsock->srcaddrlen; 
            uint16_t *portAddr = (currsock->srcport);
            memcpy(&addr->sa_data, &portAddr, addrlen);
            return 0;
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_port = currsock->srcport;
        sin->sin_addr.s_addr = htonl(0x7f000001);
        sin->sin_family = currsock->domain;
        struct sockaddr *returnVal = (struct sockaddr *)sin;
        memcpy(&addr,&returnVal, sizeof(returnVal));

        return 0;
    }
    return _getsockname(sockfd, addr, addrlen);  
}

ssize_t write(int fd, const void*buf, size_t count) {
    // printf("CLIENT CALLED: write; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        // printf("CLIENT CALLED: write; sock=%d, count=%d\n", fd, count);
        return send(fd, buf, count, 0);
    }
    return _write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    // printf("CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
    if(isFdUsed(fd)) {
        // printf("CLIENT CALLED: read; sock=%d, count=%d\n", fd, count);
        return recv(fd, buf, count, 0);
    }
    return _read(fd, buf, count);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    // printf("CLIENT CALLED: select; \n ");
    if(nfds > ANP_SOCKET_MIN_VAL) {
        if(readfds != NULL) {
            int sockfd = 0;
            for(int i = sockHead.highestFd; i >= ANP_SOCKET_MIN_VAL; i--) {
                if(FD_ISSET(i, readfds)) {
                    sockfd = i;
                    break;
                }
            }
            if(sockfd == 0) {
                printf("DID NOt FIND ANP SOCK\n");
                return _select(nfds, readfds, writefds, exceptfds, timeout);
            }
            struct socket *sock = getSocketByFd(sockfd);
            if(!timeout) {
                // _select(nfds, readfds, writefds, exceptfds, timeout);
                return 1;
            }
            if(busyWaitingSub(sock->recvPkts, timeout->tv_sec)) {
                return 1;
            }
            return 0;
        }
        return 1;
    }
    return _select(nfds, readfds, writefds, exceptfds, timeout);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) { 
    int fd = fds->fd;
    // printf("CLIENT CALLED: poll %d timout %d\n", fd, timeout);
    if(isFdUsed(fd)) {
        int pollEvent = fds->events;
        // printf("CLIENT CALLED: poll %d timout %d event %d\n", fd, timeout, pollEvent);
        if(pollEvent == 4) { //POLLOUT
            fds->revents = 4;
            return 1;
        }
        else if(pollEvent == 262) { // POLLWRBAND | POLLRDNORM | POLLNVAL | POLLPRI according to bit mask
            struct socket *sock = getSocketByFd(fd);
            fds->revents = 260;
            return 1;
        }
        else if(pollEvent == 1) { //POLLIN
            struct socket *sock = getSocketByFd(fd);
            if(sock == NULL) {
                return 0;
            }
            if(sock->pendingC) {
                fds->revents = 1;
                return 1;
            }
            if(sock->readAmount > 0) {
                fds->revents = 1;
                return 1;
            }
            if(busyWaitingSub(sock->recvPkts, timeout)) {
                fds->revents = 1;
                return 1;
            }
            return 0;
        }
        else if(pollEvent == 195) { //POLLWRNORM | POLLRDBAND | POLLHUP | POLLOUT | POLLIN
            struct socket *sock = getSocketByFd(fd);
            if(sock == NULL) {
                return 0;
            }
            if(busyWaitingSub(sock->recvPkts, timeout)) {
                fds->revents = 65;
                return 1;
            }
            return 0;
        }
        return 0;
    } 

    return _poll(fds, nfds, timeout);
}

int __poll(struct pollfd *fds, nfds_t nfds, int timeout) { //wget
    // printf("CLIENT CALLED: __poll\n");
    int fd = fds->fd;
    if(isFdUsed(fd)) {
        return poll(fds, nfds, timeout);
    }
    return ___poll(fds, nfds, timeout);
    
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // printf("CLIENT CALLED: bind; sock%d\n", sockfd);
    if(isFdUsed(sockfd)) {
        struct socket *sock = getSocketByFd(sockfd);
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sock->srcaddr = ((uint32_t)sin->sin_addr.s_addr); //TODO: maybe i need to use memcpy
        sock->srcaddrlen = addrlen;
        sock->srcport = genRandomPort();

        return 0;
    }
    return _bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    // printf("CLIENT CALLED: listen; sock%d, backlog %d\n", sockfd, backlog);
    if(isFdUsed(sockfd)) { 
        struct socket *sock = getSocketByFd(sockfd);
        sock->backlog = backlog;
        sock->isPassive = true;
        return 0;
    }
    return _listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    // printf("CLIENT CALLED: accept sock %d\n", sockfd);
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
    // printf("CLIENT CALLED: fcntl socket %d CMD = %d\n", fd, cmd);
    if(isFdUsed(fd)) {
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
            
            sock->isNonBlocking = true;

        }
        return 0;
    }
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
    return result;    
}

int fcntl(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    return fcntl64(fd, cmd, args);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    // printf("CLIENT CALLED: sendmsg %d\n", sockfd);
    return _sendmsg(sockfd, msg, flags);
}

int __sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    // printf("CLIENT CALLED: sendmmsg (Multiple) %d falgs %d\n", sockfd, flags);
    if(isFdUsed(sockfd)) {   
        for(int i = 0; i < vlen; i++) {
            if(msgvec->msg_hdr.msg_iovlen > 1) {
                // printf("OH OH, I need to implement it\n");
                exit(-1);
            }
            msgvec->msg_len = send(sockfd, msgvec->msg_hdr.msg_iov->iov_base, msgvec->msg_hdr.msg_iov->iov_len, 0)-42;
            msgvec++;
        }
        return vlen;        
    }
    return ___sendmmsg(sockfd, msgvec, vlen, flags);
}

int ioctl(int fd, unsigned long request, ...) {
    // printf("CLIENT CALLED: ioctl request %ld sock %d\n", request, fd);
    if(isFdUsed(fd)) {
        // printf("ANP ioctl %d\n", fd);
        if(request == 21531) { // FIONREAD
            va_list args;
            va_start(args, request);
            int *theArg = va_arg(args, int *);
            struct socket *sock = getSocketByFd(fd);
            *theArg = sock->readAmount;
            return 0;
        } 
        if(request == 21537) { //FIONBIO
            struct socket *sock = getSocketByFd(fd);
            sock->isNonBlocking = true;
            return 0;
        }
        else{
            // printf("request %ld not implemented\n", request);
        }
        return 0;
    }
    va_list args;
    va_start(args, request);
    void *theArg = va_arg(args, void *);
    return _ioctl(fd, request, theArg);
}

int __close (int sockfd) {
    // printf("CLIENT CALLED ___close\n");
    return 0;
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
    _fcntl = dlsym(RTLD_NEXT, "fcntl");
    _sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    ___sendmmsg = dlsym(RTLD_NEXT, "__sendmmsg");
    _ioctl = dlsym(RTLD_NEXT, "ioctl");
    ___close = dlsym(RTLD_NEXT, "__close");

}
