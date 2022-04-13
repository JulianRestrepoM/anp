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

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "common.h"

// sudo tcpdump -i wlp2s0 tcp port 43211
int main(int argc, char** argv)
{
    int server_fd = -1, ret = -1, so_far = 0;
    char *active_ip = "127.0.0.1";
    int active_port = PORT;

    struct sockaddr_in server_addr;
    char debug_buffer[INET_ADDRSTRLEN];
    char tx_buffer[TEST_BUF_SIZE];
    char rx_buffer[35000];
    bzero(tx_buffer, TEST_BUF_SIZE);
    bzero(rx_buffer, TEST_BUF_SIZE);

    printf("usage: ./anp_client ip [default: 127.0.0.1] port [default: %d]\n", PORT);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( 0 > server_fd) {
        printf("socket creation failed, errno : %d \n", errno);
        return -errno;
    }
    printf("OK: socket created, fd is %d \n", server_fd);
    bzero(&server_addr, sizeof(server_addr));
    // assign IP, PORT
    server_addr.sin_family = AF_INET;
    if(argc == 3){
        printf("setting up the IP: %s and port %d \n", argv[1], atoi(argv[2]));
        active_ip = argv[1];
        active_port = atoi(argv[2]);
    } else if (argc == 2){
        printf("setting up the IP: %s and port %d \n", argv[1], PORT);
        active_ip = argv[1];
        active_port = PORT;
    } else {
        printf("default IP: 127.0.0.1 and port %d \n", PORT);
        active_ip = "127.0.0.1";
        active_port = PORT;
    }

    ret = get_addr(active_ip, (struct sockaddr*) &server_addr);
    if( ret != 0) {
        printf("Error: Invalid IP %s \n",active_ip);
        return ret;
    }
    server_addr.sin_port = htons(active_port);

    ret = connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if ( 0 != ret) {
        printf("Error: connection with the server failed, errno %d \n", errno);
        return errno;
    }
    inet_ntop( AF_INET, &server_addr.sin_addr, debug_buffer, sizeof(debug_buffer));
    printf("OK: connected to the server at %s \n", debug_buffer);

    //send GET
    char* getHTTP = "GET / HTTP/1.1\r\nHost: www.w3.org\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n";
    int sendRet = send(server_fd, getHTTP, strlen(getHTTP), 0);
    printf("SENT GET REQUST SIZE: %d\n", sendRet);

    // printf("RECV SIZE: %ld\n",recv(server_fd, rx_buffer, sizeof(rx_buffer), 0));
    int soFar = 0;
    int htmlSize = 31322; //this is the exact size of the html from w3.org (INCLUDES: the OK 200 message) so prob subtract first message and get size? should also be + 1
    while(soFar < htmlSize) {
        ret = recv(server_fd, rx_buffer + soFar, htmlSize - soFar, 0);
        if(ret < 0) {
            printf("Error: recv failed\n");
            return -ret;
        }
        soFar += ret;
        printf("SOFAR = %d\n", soFar);
    }
    
    //write html to file.
    FILE *fp;
    fp = fopen("theStuff.html", "w");
    fputs(rx_buffer, fp);
    fclose(fp);
    // printf("%s\n", rx_buffer);
    close(server_fd);

    


    return 0;
}