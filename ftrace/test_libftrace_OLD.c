#include "libftrace.c"

// Simple little test of some parsing functions

int main()
{
  char *str1 = "this is a test that we can some Get some_bull=foo some=none bull";
  char *str2 = "ping-5025  [000] .... 44193.798484: net_dev_xmit: dev=wlp2s0 skbaddr=00000000b7c86ed6 len=98 rc=0";
  char **str_ptr = &str1;
  const char *field1 = "some";
  char *res = NULL;
  struct trace_event *tmp;

  parse_field(str_ptr, field1, &res);
  printf("Should be 'none': %s\n", res);

  tmp = trace_event_from_str(str2);
  printf("Should be '[44193.798484] finish send'\n");
  trace_event_print(tmp);
  trace_event_free(tmp);

/*
  printf("Should be 'wlp2s0' and '000000004398e8ba': '%s' '%s'\n",
    tmp->dev, tmp->skbaddr);
*/
  

  return 0;
}
