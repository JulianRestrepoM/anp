#include "udp.h"

int udpRx(struct subuff *sub) {
    struct udpHdr *hdr = udpHdrFromSub(sub);
    struct socket *currSock = getSocketByPort((hdr->destinationPort));
    if(currSock == NULL) {
        printf("UDP packet not mine, dropping\n");
        free_sub(sub);
        return 0;
    }

    return handlePacket(sub);
}

int handlePacket(struct subuff *sub) {
    printf("handlePAkcet\n");

    

    return 0;

}