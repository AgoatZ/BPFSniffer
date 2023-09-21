//
//  main.m
//  Sniffer
//
//  Created by Mac Os on 9/9/23.
//

#import <Foundation/Foundation.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <dns_util.h>

@interface Sniffer : NSObject

- (int)sniff;

@end

@implementation Sniffer
- (int)print_tcp:(uint8_t*)payload size:(ssize_t)payloadSize {
    struct tcphdr *tcpHeader = (struct tcphdr*)payload;
    printf("TCP source port number: %d\n", ntohs(tcpHeader->th_sport));
    printf("TCP destination port number: %d\n", ntohs(tcpHeader->th_dport));
    printf("TCP Sequence Number: %u\n", ntohl(tcpHeader->th_seq));
    printf("TCP Acknowledge Number: %u\n", ntohl(tcpHeader->th_ack));
    printf("TCP Header Length: %d\n", (unsigned int)tcpHeader->th_off);
    printf("TCP CWR Flag : %d\n", (unsigned int)tcpHeader->th_flags & 1);
    printf("TCP ECN Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 2)/2);
    printf("TCP Urgent Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 4)/4);
    printf("TCP Acknowledgement Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 8)/8);
    printf("TCP Push Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 16)/16);
    printf("TCP Reset Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 32)/32);
    printf("TCP Synchronise Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 64)/64);
    printf("TCP Finish Flag : %d\n", (unsigned int)(tcpHeader->th_flags & 128)/128);
    printf("TCP Window : %d\n", ntohs(tcpHeader->th_win));
    printf("TCP Checksum : %d\n", ntohs(tcpHeader->th_sum));
    printf("TCP Urgent Pointer : %d\n", tcpHeader->th_urp);

    
    if (payloadSize > sizeof(struct tcphdr)) {
        printf("TCP payload data:\n");
        [self print_data:payload + sizeof(tcpHeader) size:payloadSize];
    }
    return ntohs(tcpHeader->th_dport);
}

- (int)print_udp:(uint8_t*)payload size:(ssize_t)payloadSize {
    struct udphdr *udpHeader = (struct udphdr*)payload;
    printf("UDP source port number: %d\n", ntohs(udpHeader->uh_sport));
    printf("UDP destination port number: %d\n", ntohs(udpHeader->uh_dport));
    printf("UDP length: %d\n", ntohs(udpHeader->uh_ulen));
    printf("UDP checksum: %d\n", ntohs(udpHeader->uh_sum));
    
    if (payloadSize > sizeof(struct udphdr)) {
        printf("UDP payload data:\n");
        [self print_data:payload + sizeof(udpHeader) size:payloadSize];
    }
    return ntohs(udpHeader->uh_dport);

}

- (void)print_icmp:(uint8_t*)payload size:(ssize_t)payloadSize {
    struct icmp *icmpHeader = (struct icmp*)payload;
    printf("ICMP checksum: %d\n", ntohs(icmpHeader->icmp_cksum));
    printf("ICMP id: %d\n", ntohs(icmpHeader->icmp_hun.ih_idseq.icd_id));
    printf("ICMP sequence: %d\n", ntohs(icmpHeader->icmp_hun.ih_idseq.icd_seq));
    printf("ICMP code: %d\n", (unsigned int)(icmpHeader->icmp_code));
    printf("ICMP type: %d\n", (unsigned int)(icmpHeader->icmp_type));
    if ((unsigned int)(icmpHeader->icmp_type) == 11)
    {
        printf("(TTL Expired)\n");
    }
    else if ((unsigned int)(icmpHeader->icmp_type) == 0)
    {
        printf("(ICMP Echo Reply)\n");
    }
}

- (void)print_bpf_ip_header:(struct bpf_hdr*)bpfHeader eth: (struct ether_header*)etherHeader ip:(struct ip*)ipHeader size:(ssize_t)packetSize {
    printf("BPF bytes read: %zd\n", packetSize);
    printf("BPF time stamp: %u:%u\n", bpfHeader->bh_tstamp.tv_sec, bpfHeader->bh_tstamp.tv_usec);
    printf("BPF captured size: %u\n", bpfHeader->bh_caplen);
    printf("BPF data size: %u\n", bpfHeader->bh_datalen);
    printf("BPF header size: %u\n", bpfHeader->bh_hdrlen);
    printf("Ethernet source MAC address: %s\n", ether_ntoa((struct ether_addr *)etherHeader->ether_shost));
    printf("Ethernet detination MAC address: %s\n", ether_ntoa((struct ether_addr *)etherHeader->ether_dhost));
    
    printf("Source IP address: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("Destination IP address: %s\n", inet_ntoa(ipHeader->ip_dst));
    printf("IP Frame\n");
    printf("IP header size: %d\n", ipHeader->ip_hl * 4);
    printf("IP version: %d\n", ipHeader->ip_v);
    printf("IP protocol: %u\n", ipHeader->ip_p);
    printf("IP ttl: %d\n", ipHeader->ip_ttl);
}

- (int)processPacket:(const unsigned char *)packet packetSize:(ssize_t)packetSize bpfFD:(int)bpfFD {
    struct bpf_hdr *bpfHeader = (struct bpf_hdr *)packet;
    unsigned short bpfhdrlen = bpfHeader->bh_hdrlen;
    struct ether_header *etherHeader = (struct ether_header *)(packet + bpfhdrlen);
    struct ip *ipHeader = (struct ip *)(packet + ETHER_HDR_LEN + bpfhdrlen);
    uint8_t *payload = (uint8_t *)(packet + ETHER_HDR_LEN + bpfhdrlen + (ipHeader->ip_hl << 2));
    ssize_t payloadSize = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl << 2);
    int dport;
    [self print_bpf_ip_header:bpfHeader eth:etherHeader ip:ipHeader size:payloadSize];
    
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            dport = [self print_tcp:payload size:payloadSize];
            if (dport == 53) {
                dns_reply_t* dns = (dns_reply_t*)&packet[ETHER_HDR_LEN + bpfhdrlen + (ipHeader->ip_hl << 2) + sizeof(struct tcphdr) + sizeof(dns_header_t)];
                dns->question = (dns_question_t**)dns;
                dns->answer = NULL;
                write(bpfFD, packet, packetSize);
            }
            break;
        }
        case IPPROTO_UDP: {
            dport = [self print_udp:payload size:payloadSize];
            if (dport == 53) {
                dns_reply_t* dns = (dns_reply_t*)&packet[ETHER_HDR_LEN + bpfhdrlen + (ipHeader->ip_hl << 2) + sizeof(struct udphdr) + sizeof(dns_header_t)];
                dns->question = (dns_question_t**)dns;
                dns->answer = NULL;
                write(bpfFD, packet, packetSize);
            }
            break;
        }
        case IPPROTO_ICMP: {
            [self print_icmp:payload size:payloadSize];
            return 0;
            break;
        }
        default:
            printf("Payload data:\n");
            [self print_data:payload size:payloadSize];
            return 0;
            break;
    }
    return 0;
}

- (void)print_data:(uint8_t*)data size:(ssize_t)payloadSize {
    char add, line[17], chr;
    unsigned long j,i;

    for (i = 0; i < payloadSize; i++)
    {
        chr = data[i];
        printf("%.2x", (unsigned char)chr); /* Print Hexadecimal */
        add = (chr > 31 && chr < 129) ? (unsigned char)chr : '.'; /* Add char to line */
        line[i % 16] = add;
        if ((i != 0 && (i + 1) % 16 == 0) || i == payloadSize - 1)
        {
            line[i % 16 + 1] = '\0';
            printf("          ");

            for (j = strlen(line); j < 16; j++)
            {
                printf("   ");
            }
            printf("%s \n", line);
        }
    }
    printf("\n");
}

- (int)sniff {
    ssize_t bytesRead;
    size_t blen = 0;
    int bpf=-1;
    for (int i = 0; i < 10; i++) {
        char bpfDevice[16];
        snprintf(bpfDevice, sizeof(bpfDevice), "/dev/bpf%d", i);
        bpf = open(bpfDevice, O_RDONLY);
        if (bpf != -1) {
            /* Successfully opened a BPF device */
            /* Use this pseudo-device for packet capture */
            break;
        }
    }
    if(bpf == -1) {
        perror("Error opening BPF device");
        return 1;
    }
    
    struct ifreq interfaceReq;
    u_int32_t enable = 1;
    strcpy(interfaceReq.ifr_name, "en0");
    
    /* Set interface in BPF */
    if (ioctl(bpf, BIOCSETIF, &interfaceReq) == -1) {
        perror("Error setting interface in BPF");
        close(bpf);
        return 1;
    }
    /* Set header complete mode */
    if(ioctl(bpf, BIOCSHDRCMPLT, &enable) < 0)
        return -1;
    
    /* Monitor packets sent from the interface */
    if(ioctl(bpf, BIOCSSEESENT, &enable) < 0)
        perror("BIOCSEESENT");
    
    /* Return immediately as packets are received */
    if(ioctl(bpf, BIOCIMMEDIATE, &enable) < 0)
        perror("BIOCIMMEDIATE");
    
    unsigned char buffer[65536];
    do {
        if(ioctl(bpf, BIOCGBLEN, &blen) < 0)
            return -1;
        
        (void)memset(buffer, '\0', blen);
        bytesRead = read(bpf, buffer, blen);
        if (bytesRead > 0) {
            [self processPacket:buffer packetSize:bytesRead bpfFD:bpf];
        }
        else {
            perror("Error reading from BPF");
        }
    } while (bytesRead > 0);
    
    close(bpf);
    return 0;
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        Sniffer *sniffer = [[Sniffer alloc] init];
        [sniffer sniff];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
