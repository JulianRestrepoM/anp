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

#include "icmp.h"
#include "ip.h"
#include "utilities.h"

void icmp_rx(struct subuff *sub)
{
    //FIXME: implement your ICMP packet processing implementation here
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)
    struct icmp* icmpHeader = icmp_hdr(sub);
    struct iphdr* ih = IP_HDR_FROM_SUB(sub);

    uint16_t ogPacketCsum = icmpHeader->checksum;
    icmpHeader->checksum = 0;

    uint16_t csum = do_csum(icmpHeader, IP_PAYLOAD_LEN(ih), 0);

    if (icmpHeader->type != ICMP_V4_ECHO) {
        printf("Non-echo request, got %hx, code value %hx dropping packet\n", icmpHeader->type, icmpHeader->code);
        goto drop_pkt;
    }

    if (csum != ogPacketCsum){
        printf("Error, invalid ICMP checksum, dropping\n");
        goto drop_pkt;
    }
    icmp_reply(sub);

    drop_pkt:
    free_sub(sub);
}

void icmp_reply(struct subuff *sub)
{
    //FIXME: implement your ICMP reply implementation here
    struct iphdr *ih = IP_HDR_FROM_SUB(sub);
    struct icmp *icmpHeader = icmp_hdr(sub);

    sub_reserve(sub, IP_PAYLOAD_LEN(ih) + ETH_HDR_LEN + IP_HDR_LEN);
    sub_push(sub, IP_PAYLOAD_LEN(ih));

    icmpHeader->type = ICMP_V4_REPLY;
    icmpHeader->code = 0;
    icmpHeader->checksum = 0;
    sub->protocol = IPP_NUM_ICMP;

    icmpHeader->checksum = do_csum(icmpHeader, IP_PAYLOAD_LEN(ih), 0);

    ip_output(ih->saddr, sub);
}
