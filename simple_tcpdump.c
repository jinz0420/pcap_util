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
  int i;
  printf("\nRecevied packet: length %d bytes\n", packethdr->caplen);
  for (i = 0; i < (int)packethdr->caplen; i++) {
    if (i % 16 == 0) {
      printf("%3d: ", i);
    }
    printf(" %02x", packetptr[i]);
    if (i % 16 == 15) {
      printf("\n");
    }
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
    fprintf(stderr, "pcap_lookupnet: %s, ip=0x%x, mask=0x%x\n", errbuf, srcip,
            netmask);
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
