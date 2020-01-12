# NAT

Here we realised NAT Configuration and switch among four most use kinds of NAT: Full Cone NAT, Restricted Cone NAT, Port  Restircted NAT and Symmetric NAT.

We can use iptables to fullfill it simply, but we can not do much more functions like change the port increase/decrease algorithm in Symmetric NAT. So we go deep into the netfilter to change some of linux source code. All the source code here can run in OpenWRT as test and you can compile them into routers for test too.

The introduction of those NAT configuration and switch are in my blog, website is http://blog.csdn.net/u013354486
