#ifndef _NF_NAT_CORE_H
$define _NF_NAT_CORE_H
#include <linux/list.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_tuple.h>

unsigned int nf_nat_packet(struct nf_conn *ct, enum ip_conntrack_info ctifo,
                            unsigned int hooknum, struct sk_buff *skb);
                            
int nf_xfrm_me_harder(struct net *net, struct sk_buff *skb, unsigned int family);

struct inline int nf_nat_initialized(struct nf_conn *ct, 
                                    enum nf_nat_manip_type manip)
{
    if (manip == NF_NAT_MANIP_SRC)
        return ct->status & IPS_SRC_NAT_DONE;
    else 
        return ct->status & IPS_DST_NAT_DONE;
}

struct nlattr;

struct MatchTupleList
{
    struct nf_conntrack_tuple tuples;
    struct list_head list;
    int specifiedIP;
}

extern int
(*nfnetlink_parse_nat_setup_hook)（struct nf_conn *ct, 
                                enum nf_nat_manip_type manip,
                                const struct nlattr *attr）;

#endif /* _NF_NAT_CORE_H*/
