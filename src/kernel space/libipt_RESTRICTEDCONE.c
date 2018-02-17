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
  "RESTIRCTEDCONE target options:\n"
  "Author cty"
  "Empty here for further extension"
  );
}

static const struct xt_option_entry RESTIRCTEDCONEE_opts[] = 
{
  XTOPT_TABLEEND,
};

static void RESTIRCTEDCONE_init(struct xt_entry_target *t)
{
  struct nf_nat_ipv4_multi_range_compat *mr = ( struct nf_nat_ipv4_multi_range_compat *)t->data;
  mr->rangesize = 1;
}

static void RESTIRCTEDCONE_parse(struct xt_option_call *cb)
{
  
}

static void RESTIRCTEDCONE_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
  printf("RESTIRCTEDCONE NAT ");
}

static void RESTIRCTEDCONE_save(const void *ip, const struct xt_entry_target *target)
{
    printf("RESTIRCTEDCONE NAT ");
}

static struct xtables_target restrictedcone_tg_reg = {
  .name = "RESTIRCTEDCONE",
  .version = XTABLES_VERSION,
  .family = NFPROTO_IPV4,
  .size = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .userspace = XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat)),
  .help = RESTIRCTEDCONE_help,
  .init = RESTIRCTEDCONE_init,
  .x6_parse = RESTIRCTEDCONE_parse,
  .print = RESTIRCTEDCONE_print,
  .save = RESTIRCTEDCONE_save,
  .x6_options = RESTIRCTEDCONE_opts,
};

void _init(void)
{
  xtables_register_target(&restrictedcone_tg_reg);
}
