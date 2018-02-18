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

static void FULLCONE_parse(struct xt_option_call *cb)
{
  
}

static void FULLCONE_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
  printf("FULLCONE NAT ");
}

static void FULLCONE_save(const void *ip, const struct xt_entry_target *target)
{
    printf("FULLCONE NAT ");
}

static struct xtables_target fullcone_tg_reg = {
  .name = "FULLCONE",
  .version = XTABLES_VERSION,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .userspace = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .help = FULLCONE_help,
  .init = FULLCONE_init,
  .x6_parse = FULLCONE_parse,
  .print = FULLCONE_print,
  .save = FULLCONE_save,
  .x6_options = FULLCONE_opts,
};

void _init(void)
{
  xtables_register_target(&fullcone_tg_reg);
}
