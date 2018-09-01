#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap/pcap.h>

static volatile int running = 1;

void usage()
{
  printf("Usage: libpcap_test <device>\n");
}

void do_exit()
{
  running = 0;
}


// Returns an active, properly setup capture handle
pcap_t *get_capture(const char *dev)
{
  char err[PCAP_ERRBUF_SIZE];
  pcap_t *hdl;
  const char filt_txt[] = "icmp";
  struct bpf_program filt_prg;

  // Create the handle
  hdl = pcap_create(dev, err);
  if (hdl == NULL) {
    fprintf(stderr, "pcap_create failed for device %s with message: %s\n", dev, err);
    return NULL;
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

  return hdl;
}

void release_capture(pcap_t *hdl)
{
  pcap_close(hdl);
}

enum packet_type {
  PACKET_TYPE_NONE,
  PACKET_TYPE_ECHO_REQUEST,
  PACKET_TYPE_ECHO_RESPONSE
};

struct packet_event {
  struct timeval   ts;
  enum packet_type type;
};

void get_packet_event(pcap_t *hdl, struct packet_event *evt)
{
  struct pcap_pkthdr hdr;
  const u_char *data;

  evt->type = PACKET_TYPE_NONE;

  data = pcap_next(hdl, &hdr);

  evt->ts = hdr.ts;
}

int main(int argc, char *argv[])
{
  pcap_t *hdl;
  struct packet_event evt;

  if (argc != 2) {
    usage();
    exit(1);
  }

  signal(SIGINT, do_exit);

  hdl = get_capture(argv[1]);  
   
  while (running) {
    get_packet_event(hdl, &evt);
    printf("[%lu.%06lu] got packet!\n", evt.ts.tv_sec, evt.ts.tv_usec);
  }

  release_capture(hdl);

  printf("Done.\n");

  return 0;
}
