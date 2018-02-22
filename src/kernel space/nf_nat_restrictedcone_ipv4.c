#include <linux/types.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/timer.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/x_tables.h>

#include <net/protocol.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/ipv4/nf_nat_fullcone.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>

unsigned int
nf_nat_fullcone_match(struct nf_conntrack_tuple tuple)
{
	extern struct MatchTupleList TupleHead;
	struct list_head *pos;
	struct MatchTupleList *p;
	
	list_for_each(pos, &TupleHead.list)
	{
		p = list_entry(pos, struct MatchTupleList, list);
		if (tuple.dst.protonum == p->tuple.dst.protonum &&
		   nf_inet_addr_cmp(&tuple.dst.u3, &p->tuple.dst.u3) &&
		   p->tuple.dst.u.all == tuple.dst.u.all)
		{
			return p->tuple.src.u3.ip;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(nf_nat_fullcone_match);

unsigned int
nf_nat_fullcone_ipv4(struct sk_buff *skb, unsigned int hooknum,
		    const struct nf_nat_range *range,
		    const struct net_device *out)
{
	struct nf_conn *ct;
	struct nf_conn_nat *nat;
	enum ip_conntrack_info ctinfo;
	struct nf_nat_range newrange;
	__be32 newdst;

	//we need to monitor packets at prerouting and put dst to nf_nat_setup_info
	NF_CT_ASSERT(hooknum == NF_INET_PRE_ROUTING);

	ct = nf_ct_get(skb, &ctinfo);		//get infomationn from sockets
	nat = nfct_nat(ct);

	NF_CT_ASSERT（ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED || 
			   ctinfo == IP_CT_RELATED_REPLY)）；
				
	/* Source address is 0.0.0.0 - locally generated packet that is
	 * probably not supposed to be masqueraded.
	 */
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == 0)
		return NF_ACCEPT;
	
	newdst = nf_nat_fullcone_match(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

	if (newdst)
	{
		//transfer from original range
		memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
		memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));
		newrange.flags = range->flags | NF_NAT_RANGE_MAP_IPS;
		newrange.min_addr.ip = newdst;
		newrange.max_addr.ip = newdst;
		newrange.min_proto = range->min_proto;
		newrange.max_proto = range->max_proto;
		
		//Hnad modified range to generic setup. Change dst by normal way.
		return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_DST);
	}
	else
		return NF_ACCEPT;			
}
EXPORT_SYMBOL_GPL(nf_nat_fullcone_ipv4);

static int device_cmp(struct nf_conn *i, void *ifindex)
{
	const struct nf_conn_nat *nat = nfct_nat(i);

	if (!nat)
		return 0;
	if (nf_ct_l3num(i) != NFPROTO_IPV4)
		return 0;
	return nat->masq_index == (int)(long)ifindex;
}

static int masq_device_event(struct notifier_block *this,
			     unsigned long event,
			     void *ptr)
{
	const struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);

	if (event == NETDEV_DOWN) {
		/* Device was downed.  Search entire table for
		 * conntracks which were associated with that device,
		 * and forget them.
		 */
		WARN_ON(dev->ifindex == 0);

		nf_ct_iterate_cleanup_net(net, device_cmp,
					  (void *)(long)dev->ifindex, 0, 0);
	}

	return NOTIFY_DONE;
}

static int fullcone_inet_event(struct notifier_block *this,
			   unsigned long event,
			   void *ptr)
{
	struct in_device *idev = ((struct in_ifaddr *)ptr)->ifa_dev;
	struct netdev_notifier_info info;

	/* The masq_dev_notifier will catch the case of the device going
	 * down.  So if the inetdev is dead and being destroyed we have
	 * no work to do.  Otherwise this is an individual address removal
	 * and we have to perform the flush.
	 */
	if (idev->dead)
		return NOTIFY_DONE;

	netdev_notifier_info_init(&info, idev->dev);
	return fullcone_device_event(this, event, &info);
}

static struct notifier_block fullcone_dev_notifier = {
	.notifier_call	= fullcone_device_event,
};

static struct notifier_block fullcone_inet_notifier = {
	.notifier_call	= fullcone_inet_event,
};

static atomic_t fullcone_notifier_refcount = ATOMIC_INIT(0);

void nf_nat_fullcone_ipv4_register_notifier(void)
{
	/* check if the notifier was already set */
	if (atomic_inc_return(&masquerade_notifier_refcount) > 1)
		return;

	/* Register for device down reports */
	register_netdevice_notifier(&fullcone_dev_notifier);
	/* Register IP address change reports */
	register_inetaddr_notifier(&fullcone_inet_notifier);
}
EXPORT_SYMBOL_GPL(nf_nat_fullcone_ipv4_register_notifier);

void nf_nat_fullcone_ipv4_unregister_notifier(void)
{
	/* check if the notifier still has clients */
	if (atomic_dec_return(&masquerade_notifier_refcount) > 0)
		return;

	unregister_netdevice_notifier(&fullcone_dev_notifier);
	unregister_inetaddr_notifier(&fullcone_inet_notifier);
}
EXPORT_SYMBOL_GPL(nf_nat_fullcone_ipv4_unregister_notifier);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ty Chen <tianyuch@hotmail.com>");
