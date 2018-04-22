#define pr_fmt(fmt) KBUILD_MODNAME ":" fmt
#include <linux/types.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/route.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/ipv4/nf_nat_masquerade.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chen tianyu <tianyuch@hotmail.com>");
MODULE_DESCRIPTION("Xtables: automatic-address SNAT for fullcone NAT");

/* FIXME: Multiple targets. --RR */
static int fullcone_tg_check(const struct xt_tgchk_param *par)
{
	const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;

	if (mr->range[0].flags & NF_NAT_RANGE_MAP_IPS) {
		pr_debug("bad MAP_IPS.\n");
		return -EINVAL;
	}
	if (mr->rangesize != 1) {
		pr_debug("bad rangesize %u\n", mr->rangesize);
		return -EINVAL;
	}
	return nf_ct_netns_get(par->net, par->family);
}

static unsigned int
fullcone_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct nf_nat_range range;
	const struct nf_nat_ipv4_multi_range_compat *mr;

	mr = par->targinfo;
	range.flags = mr->range[0].flags;
	range.min_proto = mr->range[0].min;
	range.max_proto = mr->range[0].max;

	return nf_nat_fullcone_ipv4(skb, xt_hooknum(par), &range,
				      xt_out(par));
}

static void fullcone_tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static struct xt_target fullcone_tg_reg __read_mostly = {
	.name		= "FULLCONE",
	.family		= NFPROTO_IPV4,
	.target		= fullcone_tg,
	.targetsize	= sizeof(struct nf_nat_ipv4_multi_range_compat),
	.table		= "nat",
	.hooks		= 1 << NF_INET_PRE_ROUTING,
	.checkentry	= fullcone_tg_check,
	.destroy	= fullcone_tg_destroy,
	.me		= THIS_MODULE,
};

static int __init fullcone_tg_init(void)
{
	int ret;

	ret = xt_register_target(&fullcone_tg_reg);

	if (ret == 0)
		nf_nat_fullcone_ipv4_register_notifier();

	return ret;
}

static void __exit fullcone_tg_exit(void)
{
	xt_unregister_target(&fullcone_tg_reg);
	nf_nat_fullcone_ipv4_unregister_notifier();
}

module_init(fullcone_tg_init);
module_exit(fullcone_tg_exit);
