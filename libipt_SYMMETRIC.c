#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <limits.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nv_nat.h>

enum{
  O_PACE = 0,
};

static void SYMMETRIC_help(void)
{
  printf(
  "Symmetric target options:\n"
  "Author: cty"
  "Empty here for further extension"
  );
}

static const struct xt_option_entry SYMMETRIC_opts[] = 
{
  {.name = "pace", .id = O_PACE, .type = XTTYPE_STRING},
  XTOPT_TABLEEND,
};

static void SYMMETRIC_init(struct xt_entry_target *t)
{
  struct nf_nat_ipv4_multi_range_compat *mr = ( struct nf_nat_ipv4_multi_range_compat *)t->data;
  mr->rangesize = 1;
}

static void SYMMETRIC_parse(struct xt_option_call *cb)
{
  
}

static void SYMMETRIC_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
  printf("FULLCONE NAT ");
}

static void SYMMETRIC_save(const void *ip, const struct xt_entry_target *target)
{
    printf("FULLCONE NAT ");
}

static struct xtables_target symmetric_tg_reg = {
  .name = "SYMMETRIC",
  .version = XTABLES_VERSION,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .userspace = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .help = SYMMETRIC_help,
  .init = SYMMETRIC_init,
  .x6_parse = SYMMETRIC_parse,
  .print = SYMMETRIC_print,
  .save = SYMMETRIC_save,
  .x6_options = SYMMETRIC_opts,
};

void _init(void)
{
  xtables_register_target(&symmetric_tg_reg);
}
