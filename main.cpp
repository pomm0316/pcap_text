#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192 //

typedef uint8_t ethdst[6];
typedef uint8_t Ipch[4];

typedef struct ethernet {
    ethdst dst;
    ethdst src;
    uint16_t type;
};

typedef struct Ipcheck {
    uint8_t vhl;
    uint8_t tos;
    uint16_t packlength;
    uint16_t identifier;
    uint16_t fragoff;
    uint8_t ttl;
    uint8_t proto;
    uint16_t chsum;
    Ipch src_ip;
    Ipch dst_ip;
} ;

typedef struct Tcpcheck{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t wind;
    uint16_t checksum;
    uint16_t urptr;
};

void mac_print(ethdst addr, char* buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void Arr_print(int start, int l, const uint8_t *packet) {
    for (int i = 0; i < l; i++) {
        printf("%02x ", packet[start + i]);
    }
}

void Ether_print(ethernet *eth) {
    char mac_str[18];
    mac_print(eth->dst, mac_str);
    printf("Dst MAC: %s\n", mac_str);
    mac_print(eth->src, mac_str);
    printf("Src MAC: %s\n", mac_str);
    printf("Type: IPv4(0x%04x)\n", ntohs(eth->type));
}

void Ip_print(Ipcheck *ip) {
    char ip_str[20];
    inet_ntop(AF_INET, &(ip->src_ip), ip_str, sizeof(ip_str));
    printf("Src IP: %s\n", ip_str);
    inet_ntop(AF_INET, &(ip->dst_ip), ip_str, sizeof(ip_str));
    printf("Dst IP: %s\n", ip_str);
}

void TCP_print(Tcpcheck *tcp) {
    printf("Src Port: %d\n", ntohs(tcp->src_port));
    printf("Dst Port: %d\n", ntohs(tcp->dst_port));
}

void TcpData_print(int pl, int hl, const uint8_t *packet) {
    int diff = pl - hl;
    if (diff > 0) {
        printf("TCP Data: ");
        if (diff > 10) diff = 10;
        Arr_print(hl, diff, packet);
        putchar('\n');
    }
}

void usage() {
    printf("syntax: <interface>\n");
    printf("sample: wlan0\n");
}

void PacketData(const struct pcap_pkthdr *header, const uint8_t *packet) {
    ethernet *eth = (ethernet *) packet;
    if (ntohs(eth->type) == 0x0800) {
        Ipcheck *ip = (Ipcheck *) (packet + sizeof(ethernet));
        if (ip->proto == 0x06) {
            Tcpcheck *tcp = (Tcpcheck *) (packet + sizeof(ethernet) + sizeof(Ipcheck));
            int ip_hl = (ip->vhl & 0xF) * 4;
            int tcp_hl = ((tcp->flags & 0xF0) >> 4) * 4;
            int hl = 14 + ip_hl + tcp_hl;
            printf("TCPData---------------------------------\n");
            Ether_print(eth);
            Ip_print(ip);
            TCP_print(tcp);
            TcpData_print(header->caplen, hl, packet);
            printf("----------------------------------------\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *packet;
    char err_buf[PCAP_ERRBUF_SIZE];
    int res = 0;
    pcap_t *handle = NULL;

    printf("Opening device %s\n", argv[1]);
    handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 0, 512, err_buf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", argv[1], err_buf);
        return -1;
    }

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        PacketData(header, packet);
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}


