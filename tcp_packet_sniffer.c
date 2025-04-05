#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>

struct ethheader {
  u_char  ether_dhost[6];
  u_char  ether_shost[6];
  u_short ether_type;
};

struct ipheader {
  unsigned char      iph_ihl:4, iph_ver:4;
  unsigned char      iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned short int iph_flag:3, iph_offset:13;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol;
  unsigned short int iph_chksum;
  struct  in_addr    iph_sourceip;
  struct  in_addr    iph_destip;
};

struct tcpheader {
  u_short th_sport;
  u_short th_dport;
  u_int   th_seq;
  u_int   th_ack;
  u_char  th_off:4, th_x2:4;
  u_char  th_flags;
  u_short th_win;
  u_short th_sum;
  u_short th_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;
    if (ip->iph_protocol != IPPROTO_TCP) return;

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = tcp->th_off * 4;

    int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    if (header->caplen < total_header_size) {
      printf("Malformed packet (header too short)\n\n");
      return;
    }

    const u_char *payload = packet + total_header_size;
    int payload_len = header->caplen - total_header_size;

    printf("==============================================\n\n");
    printf("Ethernet Header:\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("IP Header:\n");
    printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("TCP Header:\n");
    printf("   Src Port: %u\n", ntohs(tcp->th_sport));
    printf("   Dst Port: %u\n", ntohs(tcp->th_dport));

    printf("Message Payload (%d bytes): ", payload_len);
    for (int i = 0; i < payload_len && i < 32; i++) {
      printf("%c", isprint(payload[i]) ? payload[i] : '.');
    }
    printf("\n\n");
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net, mask;

  const char *dev = "ens33";

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return 2;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return 2;
  }

  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);
  return 0;
}
