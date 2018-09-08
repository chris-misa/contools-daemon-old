#include "libftrace.c"

// Simple little test of some parsing functions

int main()
{
  char *str1 = "this is a test that we can some Get some_bull=foo some=none bull";
  char *str2 = "ping-10508 [000] .... 31011.774831: net_dev_start_xmit: dev=wlp2s0 queue_mapping=2 skbaddr=000000004398e8ba vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0800 ip_summed=0 len=98 data_len=0 network_offset=14 transport_offset_valid=1 transport_offset=34 tx_flags=0 gso_size=0 gso_segs=0 gso_type=0x0";
  char **str_ptr = &str1;
  const char *field1 = "some";
  char *res = NULL;
  struct trace_event *tmp;

  parse_field(str_ptr, field1, &res);
  printf("Should be 'none': %s\n", res);

  tmp = trace_event_from_str(str2);
  printf("Should be 'wlp2s0' and '000000004398e8ba': '%s' '%s'\n",
    tmp->dev, tmp->skbaddr);
  printf("Should be '31011.774831': '%lu.%06lu'\n", tmp->ts.tv_sec, tmp->ts.tv_usec);

  return 0;
}
