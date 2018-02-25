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
icmp_reply_hook_func(unsigned int hook,
 				struct sk_buff **skb,
 				const struct net_device *in,
				const struct net_device *out,
 				int (*okfn)(struct sk_buff *))
     
{
	const struct iphdr *iph;
	struct icmphdr *icmph;
	 
	if ((*skb)->len < sizeof(struct iphdr) ||
	    ip_hdrlen(*skb) < sizeof(struct iphdr))
		return NF_ACCEPT;

	iph = ip_hdr(*skb);
	icmph = (struct icmphdr *)(iph + 1);
	if (1 == iph->protocol)
	{
		if(0 == icmph->type)
		{
			if((icmph->un.echo.sequence) % (0x9) == 0)               
			//drop every 9 packets
			{
				printk("----drop %x---\n", icmph->un.echo.sequence);
				return NF_DROP;
			}
		}
	}
	return NF_ACCEPT;
}
 
static struct nf_hook_ops __read_mostly  icmp_reply_hook =
{
		.hook 		= icmp_reply_hook_func,
		//.owner 		= THIS_MODULE,
		.pf 		= PF_INET,
		.hooknum 	= NF_INET_LOCAL_IN,
		.priority 	= NF_IP_PRI_FIRST,
};


static int __init icmp_reply_hook_init(void)
{
	printk(KERN_INFO"---init---\n");
	return nf_register_hook(&icmp_reply_hook);
}


static void __exit icmp_reply_hook_exit(void)
{
	printk(KERN_INFO"---exit---\n");
	nf_unregister_hook(&icmp_reply_hook);
}
 
module_init(icmp_reply_hook_init);
module_exit(icmp_reply_hook_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Tianyu");
MODULE_DESCRIPTION("Drop hook test 1.0");
