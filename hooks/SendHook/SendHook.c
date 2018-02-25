#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <net/route.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chen tianyu");
MODULE_DESCRIPTION("hook test 2.0");

#define    ETH    "eth0"  //interface name
#define    SIP     "192.168.6.130"
#define    DIP     "118.6.24.132"
#define    SPORT   39804
#define    DPORT   6980
unsigned char   SMAC[ETH_ALEN] = {0x00,0x0C,0x29,0x33,0x2C,0x3C}; //network device MAC addr
unsigned char   DMAC[ETH_ALEN] = {0x00,0x50,0x56,0xF4,0x8B,0xB3}; //default gateway MAC addr

static int build_and_xmit_udp(char * eth, u_char * smac, u_char * dmac,
							 u_char * pkt, int pkt_len,u_long sip, u_long dip,
							 u_short sport, u_short dport)
{
	struct sk_buff * skb = NULL;
	struct net_device * dev = NULL;
	struct ethhdr * ethdr = NULL;
	struct iphdr * iph = NULL;
	struct udphdr * udph = NULL;
	u_char * pdata = NULL;
  
	if(NULL == smac || NULL == dmac)
		goto out;

	if(NULL == (dev= dev_get_by_name(eth)))
		goto out;

	skb = alloc_skb(pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(dev), GFP_ATOMIC);

	if(NULL == skb)
		goto out;
	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb->dev = dev;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->priority = 0;

	skb->nh.iph = (struct iphdr*)skb_put(skb, sizeof(struct iphdr));
	skb->h.uh = (struct udphdr*)skb_put(skb, sizeof(struct udphdr));

	pdata = skb_put(skb, pkt_len);
	{
		if(NULL != pkt)
			memcpy(pdata, pkt, pkt_len);
	}

  
	udph = (struct udphdr *)skb->h.uh;
	memset(udph, 0, sizeof(struct udphdr));
	udph->source = sport;
	udph->dest = dport;
	skb->csum = 0;
	udph->len = htons(sizeof(struct udphdr)+pkt_len);
	udph->check = 0;

	iph = (struct iphdr*)skb->nh.iph;
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr)>>2;
	iph->frag_off = 0;
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->daddr = dip;
	iph->saddr = sip;
	iph->ttl = 0x40;
	iph->tot_len = __constant_htons(skb->len);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);

	skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);
	udph->check = csum_tcpudp_magic(sip, dip, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);

	skb->mac.raw = skb_push(skb, 14);
	ethdr = (struct ethhdr *)skb->mac.raw;
	memcpy(ethdr->h_dest, dmac, ETH_ALEN);
	memcpy(ethdr->h_source, smac, ETH_ALEN);
	ethdr->h_proto = __constant_htons(ETH_P_IP);

	if(0 > dev_queue_xmit(skb))
		goto out;

out:
	if(NULL != skb)
	{
		dev_put (dev);
		kfree_skb (skb);
	}
	return(NF_ACCEPT);
}

static int pktcnt = 0;

static unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	const struct iphdr *iph = (*skb)->nh.iph;
	int ret = NF_ACCEPT;

	if(iph->protocol == 1){
	   atomic_inc(&pktcnt);
	   if(pktcnt%5 == 0){
			printk(KERN_INFO "Sending the %d udp pkt !\n",pktcnt/5);
			ret = build_and_xmit_udp(ETH,SMAC,DMAC,"hello",5,in_aton(SIP),in_aton(DIP),htons(SPORT),htons(DPORT));
	   }
	}
	return ret;
}

static struct nf_hook_ops nfho={
	.hook           = hook_func,
	.owner          = THIS_MODULE,
	.pf             = PF_INET,
	.hooknum        = NF_IP_LOCAL_OUT,
	.priority       = NF_IP_PRI_FIRST,
};

static int __init myhook_init(void)
{
    return nf_register_hook(&nfho);
}

static void __exit myhook_fini(void)
{
    nf_unregister_hook(&nfho);
}

module_init(myhook_init);
module_exit(myhook_fini);


