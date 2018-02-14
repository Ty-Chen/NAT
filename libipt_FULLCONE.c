#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nv_nat.h>

static void FULLCONE_help(void)
{
  printf(
  "FULLCONE target options:\n"
  "Author cty"
  "Empty here for further extension"
  );
}

static const struct xt_option_entry FULLCONE_opts[] = 
{
  XTOPT_TABLEEND,
};

static void FULLCONE_init(struct xt_entry_target *t)
{
  struct nf_nat_ipv4_multi_range_compat *mr = ( struct nf_nat_ipv4_multi_range_compat *)t->data;
  mr->rangesize = 1;
}
