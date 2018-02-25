//’Hello World’ v2 netfilter hooks example  
//For any packet, get the ip header and check the protocol field  
//if the protocol number equal to UDP (17), log in var/log/messages  
//default action of module to let all packets through  
       
#include <linux/kernel.h>  
#include <linux/module.h>  
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/skbuff.h>  
#include <linux/udp.h>  
#include <linux/ip.h>  

#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) ((unsigned char *) &addr)[0], ((unsigned char *) &addr)[1], ((unsigned char *) &addr)[2], ((unsigned char *) &addr)[3]
       
#define pre_routing NF_INET_PRE_ROUTING 
#define local_in NF_INET_LOCAL_IN 
#define forward NF_INET_FORWARD
#define local_out NF_INET_LOCAL_OUT 
#define post_routing NF_INET_POST_ROUTING 

#define ICMP_proto 1
#define TCP_proto 6
#define UDP_proto 17

static int pktcnt = 0;              //counter
struct udphdr *udp_header;          //udp header struct (not used)  
struct iphdr *ip_header;            //ip header struct  
       
unsigned int 
hook_func(unsigned int hooknum, 
        struct sk_buff *skb, 
        const struct net_device *in, 
        const struct net_device *out, 
        int (*okfn)(struct sk_buff *))  
{   
    //grab network header using accessor 
    ip_header = (struct iphdr *)skb_network_header(skb);    
                
     //if(!sock_buff) { return NF_ACCEPT;}        
    if (UDP_proto == ip_header->protocol) 
    {  
        udp_header = (struct udphdr *)skb_transport_header(skb);  
        //grab transport header        
        printk(KERN_INFO "got udp packet \n");     
        //log we’ve got udp packet to /var/log/messages  
        return NF_DROP;  
    }  
                     
    return NF_ACCEPT;  
}  

static struct nf_hook_ops nfho =    //net filter hook option struct
{
    .hook       = hook_func,  
    .hooknum    = local_out, 
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,  
};     
       
static int __init udp_drop_init(void)  
{         
    printk(KERN_INFO"---init---\n");               
    return nf_register_hook(&nfho); 
}  
       
static void __exit udp_drop_exit(void)  
{  
    printk(KERN_INFO"---exit---\n"); 
    nf_unregister_hook(&nfho);       
}  
  
module_init(udp_drop_init);
module_exit(udp_drop_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Tianyu");
MODULE_DESCRIPTION("UDP hook test 1.0");
