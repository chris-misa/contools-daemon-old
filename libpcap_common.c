#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// #define DEBUG

// Returns an active, properly setup capture handle
pcap_t *get_capture(const char *dev)
{
  char err[PCAP_ERRBUF_SIZE];
  pcap_t *hdl;
  const char filt_txt[] = "icmp";
  struct bpf_program filt_prg;
  int res;
  int lnk_type;

  // Create the handle
  hdl = pcap_create(dev, err);
  if (hdl == NULL) {
    fprintf(stderr, "pcap_create failed for device %s with message: %s\n", dev, err);
    return NULL;
  }

  // Set time stamp type
  pcap_set_tstamp_type(hdl, PCAP_TSTAMP_HOST_LOWPREC);

  // Activate
  res = pcap_activate(hdl);
  if (res) {
    fprintf(stderr, "pcap_activate returned nonzero message: %s\n", pcap_statustostr(res));
    if (res < 0) {
      return NULL;
    }
  }

  // Compile the filter
  if (pcap_compile(hdl, &filt_prg, filt_txt, 0, PCAP_NETMASK_UNKNOWN)) {
    fprintf(stderr, "pcap_compile failed for program %s with message: %s\n", filt_txt, pcap_geterr(hdl));
    return NULL;
  } 

  // Set the filter
  if (pcap_setfilter(hdl, &filt_prg)) {
    fprintf(stderr, "pcap_setfilter failed with message: %s\n", pcap_geterr(hdl));
    return NULL;
  }

  // Free the filter
  pcap_freecode(&filt_prg);

  // Check the data link type
  lnk_type = pcap_datalink(hdl);
  if (lnk_type != DLT_EN10MB) {
    fprintf(stderr, "Warning: non-ethernet data link\n");
  }

  return hdl;
}

void release_capture(pcap_t *hdl)
{
  pcap_close(hdl);
}

// Parse icmp packets and pack relevant info into a struct
enum packet_type {
  PACKET_TYPE_NONE,
  PACKET_TYPE_ECHO_REQUEST,
  PACKET_TYPE_ECHO_REPLY
};

struct packet_event {
  struct timeval   ts;
  enum packet_type type;
};

// Returns nonzero if successfully captured icmp echo event
int get_packet_event(pcap_t *hdl, struct packet_event *evt)
{
  struct pcap_pkthdr pkt_hdr;
  const u_char *data;
  struct ether_header *eth_hdr;
  struct ip *ip_hdr;
  struct icmp *icmp_hdr;
  int i;

  evt->type = PACKET_TYPE_NONE;

  data = pcap_next(hdl, &pkt_hdr);
  
  // Fail if no data
  if (data == NULL) {
    return 0;
  }

  // Copy off the time stamp
  evt->ts = pkt_hdr.ts;

  // Parse ethernet header
  eth_hdr = (struct ether_header *)data;
  // Fail if not IP packet
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
    return 0;
  }
#ifdef DEBUG
  printf("ethernet src: %s ", ether_ntoa((struct ether_addr *)&eth_hdr->ether_shost));
  printf("dst: %s ", ether_ntoa((struct ether_addr *)&eth_hdr->ether_dhost));
  printf("type: %X\n", ntohs(eth_hdr->ether_type));
#endif

  // Parse ip header
  ip_hdr = (struct ip *)(data + sizeof(struct ether_header));
  // Fail if not ICMP packet
  if (ip_hdr->ip_p != 1) {
    return 0;
  }
#ifdef DEBUG
  printf("ip proto: %X ", ip_hdr->ip_p);
  printf("src: %s ", inet_ntoa(ip_hdr->ip_src));
  printf("dst: %s\n", inet_ntoa(ip_hdr->ip_dst));
#endif

  // Parse icmp header
  icmp_hdr = (struct icmp *)(data + sizeof(struct ether_header) + sizeof(struct ip));
#ifdef DEBUG
  printf("icmp message type: %d\n", icmp_hdr->icmp_type);
#endif
  switch (icmp_hdr->icmp_type) {
    case ICMP_ECHO:
      evt->type = PACKET_TYPE_ECHO_REQUEST;
      break;
    case ICMP_ECHOREPLY:
      evt->type = PACKET_TYPE_ECHO_REPLY;
      break;
    default:
      // Fail if not echo request or reply
      return 0;
      break;
  }

  return 1;
}
