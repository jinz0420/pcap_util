#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int linkhdrlen;
int packets;

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr,
                    const u_char *packetptr) {
  struct ip *iphdr;
  struct icmp *icmphdr;
  struct tcphdr *tcphdr;
  struct udphdr *udphdr;
  char iphdrInfo[256];
  char srcip[256];
  char dstip[256];

  // Skip the datalink layer header and get the IP header fields.
  packetptr += linkhdrlen;
  iphdr = (struct ip *)packetptr;
  strcpy(srcip, inet_ntoa(iphdr->ip_src));
  strcpy(dstip, inet_ntoa(iphdr->ip_dst));
  sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
          ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4 * iphdr->ip_hl,
          ntohs(iphdr->ip_len));

  // Advance to the transport layer header then parse and display
  // the fields based on the type of hearder: tcp, udp or icmp.
  packetptr += 4 * iphdr->ip_hl;
  switch (iphdr->ip_p) {
  case IPPROTO_TCP:
    tcphdr = (struct tcphdr *)packetptr;
    printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport), dstip,
           ntohs(tcphdr->th_dport));
    printf("%s\n", iphdrInfo);
    printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
           (tcphdr->th_flags & TH_URG ? 'U' : '*'),
           (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
           (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
           (tcphdr->th_flags & TH_RST ? 'R' : '*'),
           (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
           (tcphdr->th_flags & TH_SYN ? 'F' : '*'), ntohl(tcphdr->th_seq),
           ntohl(tcphdr->th_ack), ntohs(tcphdr->th_win), 4 * tcphdr->th_off);
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
    packets += 1;
    break;

  case IPPROTO_UDP:
    udphdr = (struct udphdr *)packetptr;
    printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport), dstip,
           ntohs(udphdr->uh_dport));
    printf("%s\n", iphdrInfo);
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
    packets += 1;
    break;

  case IPPROTO_ICMP:
    icmphdr = (struct icmp *)packetptr;
    printf("ICMP %s -> %s\n", srcip, dstip);
    printf("%s\n", iphdrInfo);
    printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type,
           icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id),
           ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
    packets += 1;
    break;
  }
}

int main(int argc, char **argv) {
  char device[256];
  char filter[256];
  int count = 0;
  int opt;

  *device = 0;
  *filter = 0;

  // Get the command line options, if any
  while ((opt = getopt(argc, argv, "hi:n:")) != -1) {
    switch (opt) {
    case 'h':
      printf("usage: %s [-h] [-i interface] [-n count] [BPF expression]\n",
             argv[0]);
      exit(0);
      break;
    case 'i':
      strcpy(device, optarg);
      break;
    case 'n':
      count = atoi(optarg);
      break;
    }
  }

  for (int i = optind; i < argc; i++) {
    strcat(filter, argv[i]);
    strcat(filter, " ");
  }

  pcap_if_t *pdev;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (device[0] == 0) {
    if (pcap_findalldevs(&pdev, errbuf)) {
      fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
      return -1;
    }
    strcpy(device, pdev[0].name);
  }

  bpf_u_int32 netmask;
  bpf_u_int32 srcip;
  struct bpf_program bpf;

  if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
    return -1;
  }

  pcap_t *handle;

  handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
    return -1;
  }

  if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
    fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
    return -1;
  }

  if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
    fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
    return -1;
  }

  int linktype;
  if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
    fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
    return -1;
  }

  switch (linktype) {
  case DLT_NULL:
    linkhdrlen = 4;
    break;

  case DLT_EN10MB:
    linkhdrlen = 14;
    break;

  case DLT_SLIP:
  case DLT_PPP:
    linkhdrlen = 24;
    break;

  default:
    printf("Unsupported datalink (%d)\n", linktype);
    linkhdrlen = 0;
  }

  if (pcap_loop(handle, count, packet_handler, (u_char *)NULL) < 0) {
    fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
    return -1;
  }
  return 0;
}
