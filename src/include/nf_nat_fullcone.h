#ifndef _NF_NAT_FULLCONE_IPV4_H_
$define _NF_NAT_FULLCONE_IPV4_H_

#include <net/netfilter/nf_nat.h>
unsigned int
nf_nat_fullcone_ipv4(struct sk_buff*skb, unsigned int hooknum,
                    const struct nf_nat_range *range,
                    const struct net_device *out);
                    
void nf_nat_fullcone_ipv4_register_notifer(void);
void nf_nat_fullcone_ipv4_unregister_notifer(void);

#endif
