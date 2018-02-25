#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/icmp.h>
#include <net/ip.h>

static unsigned int
icmp_request_hook_func(unsigned int hook,
				 struct sk_buff **skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 int (*okfn)(struct sk_buff *))
     
{
	const struct iphdr *iph;
	struct icmphdr *icmph;
	 
	if ((*skb)->len < sizeof(struct iphdr) ||
	    ip_hdrlen(*skb) < sizeof(struct iphdr))	 
	{
	 	return NF_ACCEPT;
	}   
		
	iph = ip_hdr(*skb);
	icmph = (struct icmphdr *)(iph + 1);
	if(1 == iph->protocol)
	{
		if( 8 == icmph->type)
		{
			if((icmph->un.echo.sequence) % 5 == 0)      
			 //drop every 5 packets
			{
				printk("----drop---\n");
				return NF_DROP;
			}
		}
	}
	return NF_ACCEPT;
}
 
static struct nf_hook_ops __read_mostly  icmp_request_hook =
{
		.hook 			= icmp_request_hook_func,
		.owner 			= THIS_MODULE,
		.pf 			= PF_INET,
		.hooknum	    = NF_IP_LOCAL_OUT,
		.priority 		= NF_IP_PRI_FIRST,
};

static int __init icmp_request_init(void)
{
	printk(KERN_INFO"---init---\n");
	return nf_register_hook(&icmp_request_hook);
}

static void __exit icmp_request_exit(void )
{
	printk(KERN_INFO"---exit---\n");
	nf_unregister_hook(&icmp_request_hook);
}
 
module_init(icmp_request_init);
module_exit(icmp_request_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Tianyu");
MODULE_DESCRIPTION("Drop hook test 1.0");