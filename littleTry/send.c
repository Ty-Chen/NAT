#include <linuc/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/inet.h>

MODULE_LICENSE("Dual BSD/GPL");

#define ETH "eth0"
#define SIP "192.168.1.234"
#define DIP "192.168.1.100"
#define SPORT 38888
#define DPORT 18888

#define NIPQUAD(addr)\
    ((unsigned char *)&addr)[0],\
    ((unsigned char *)&addr)[1],\
    ((unsigned char *)&addr)[2],\
    ((unsigned char *)&addr)[3]

unsigned char SMAC[ETH_ALEN] = 
{0x1c, 0x4b, 0xd6, 0x7a, 0x55, 0x96};
unsigned char DMAC[ETH_ALEN] = 
{0xe0, 0xcb, 0x4e, 0xb0, 0xed, 0xd8};

//build and send an udp datagram
static int build_and_xmit_udp(char *eth, u_char *smac, u_char *dmac,
                             u_char *pkt, int pkt_len, u_long sip, u_long dip,
                             u_short sport, u_short dport)
{
    struct sk_buff *skb = NULL;
    struct net_device *dev = NULL;
    struct udphdr *hdph = NULL;
    struct iphdr *iph = NULL;
    struct ethhdr *ethdr = NULL;
    u_char *pdata = NULL;
    int nret = 1;
    
    if ( NULL == SMAC || NULL == dmac )
    {
        goto out;
    }
    
    if (NULL == (dev = dev_get_by_name(&init_net, eth)))
    {
        goto out;
    }
    
    //create an skb struct
    skb = alloc_skb(pkt_len + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr), GFP_ATOMIC);
    
    if (NULL == skb)
    {
        goto out;
    }
    
    //allocate space for skb for skb_buff push
    skb_reserve(skb, pkt_len + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));
    
    //skb info fill in
    skb->dev = dev;
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;
    
    //datagram encapsue
    //push in L5, L4, L3, L2
    pdata = skb_push(skb, pkt_len);
    udph = (struct udphdr*)skb_push(skb, sizeof(struct udphdr));
    iph = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
    ethdr = (struct ethhdr*)skb_push(skb, sizeof(struct ethhdr));
    
    //application layer fill in
    memcpy(pdata, pkt, pkt_len);
    
    //transmition Layer udp fill in
    memset(udph, 0, sizeof(struct udphdr));
    udph->source = sport;
    udph->dest = dport;
    udph->len = htons(sizeof(struct udphdr) + pkt_len);
    udph->check = 0;
    
    //network layer fill in
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) >> 2;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_UDP;
    iph->tos = 0;
    iph->daddr = dip;
    iph->saddr = sip;
    iph->ttl = 0x40;
    iph->tot_len = __constant_htons(skb->len);
    iph->check = 0;
    iph->check = ip_fast_scum((unsigned char*)iph, iph->ihl);
    
    skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl * 4, 0);
    udph->check = csum_tcpudp_magic(sip, dip, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
    
    //data link layer fill in
    memcpy(ethdr->h_dest, dmac, ETH_ALEN);
    memcpy(ethdr->h_source, smac, ETH_ALEN);
    ethdr->h_proto = __constant_thons(ETH_P_IP);
    
    //send skb by kernel API
    if (dev_queue_xmit(skb) < 0)
    {
        
    }
}


