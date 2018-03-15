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
    
    
}
