#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#define pre_routing NF_INET_PRE_ROUTING 
#define local_in NF_INET_LOCAL_IN 
#define forward NF_INET_FORWARD
#define local_out NF_INET_LOCAL_OUT 
#define post_routing NF_INET_POST_ROUTING 

#define ICMP_proto 1
#define TCP_proto 6
#define UDP_proto 17

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) ((unsigned char *) &addr)[0], ((unsigned char *) &addr)[1], ((unsigned char *) &addr)[2], ((unsigned char *) &addr)[3]

static int pktcnt = 0;
//drop ICMP every 3 packets
static unsigned int 
myhook_func(unsigned int hooknum, 
         struct sk_buff **skb, 
         const struct net_device *in, 
         const struct net_device *out, 
         int (*okfn)(struct sk_buff *))
{
  	const struct iphdr *iph = (struct iphdr*)skb_network_header(skb);
   	if (ICMP_proto == iph->protocol )
   	{
    	atomic_inc(&pktcnt);      	
     	if (1 == pktcnt % 3)
      	{     	
      		printk("%d: Pass an ICMP pkt, from %u.%u.%u.%u to %u.%u.%u.%u !\n "
      			, pktcnt, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
      		return NF_ACCEPT;
      	}
      	if (2 == pktcnt % 3)
      	{
      		((unsigned char *) &iph->daddr)[3] = 2;
      		printk("%d: Pass an ICMP pkt but change daddr, from %u.%u.%u.%u to %u.%u.%u.%u !\n "
      			, pktcnt, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
      		return NF_ACCEPT;
      	}
      	if (0 == pktcnt % 3)
     	{
           	printk(KERN_INFO "%d: drop an ICMP pkt from %u.%u.%u.%u to %u.%u.%u.%u !\n", 
                pktcnt, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
           	return NF_DROP;
      	}

   	}
   	return NF_ACCEPT;
}
 
static struct nf_hook_ops nfho =
{
        .hook           = myhook_func,  //our cb function
       // .owner          = THIS_MODULE,
        .pf             = PF_INET,
        .hooknum        = local_out, //sniffer packets in local out.
        .priority       = NF_IP_PRI_FIRST,  //highest priority
};
 
static int __init myhook_init(void)
{
    printk(KERN_INFO"---init---\n");
    return nf_register_hook(&nfho);
}
 
static void __exit myhook_exit(void)
{
    printk(KERN_INFO"---exit---\n");
    nf_unregister_hook(&nfho);
}
 
module_init(myhook_init);
module_exit(myhook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Tianyu");
MODULE_DESCRIPTION("Drop hook test 1.0");
