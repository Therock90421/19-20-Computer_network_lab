#include "ip.h"
#include "icmp.h"
#include "rtable.h"
#include "arp.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>



// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stderr, "TODO: handle ip packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 IP_dest_addr = ntohl(ip->daddr);
	if (IP_dest_addr == iface->ip) 
	{
		// fprintf(stderr, "TODO: reply to the sender if it is ping packet.\n");
		u8 type = (u8)*(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip));
		if (type == ICMP_ECHOREQUEST) 
		{
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		} 
		else 
		{
			free(packet);
		}
	}
	else 
	{
		rt_entry_t *rt = longest_prefix_match(IP_dest_addr);
	    if (rt) 
	    {
		    //struct iphdr *hdr = packet_to_ip_hdr(packet);
		    u8 ttl = ip->ttl;
		    ip->ttl = --ttl;
		    if (ttl == 0) 
		    {
			    icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			    return;
		    }
		    ip->checksum = ip_checksum(ip);
		    if (rt->gw) iface_send_packet_by_arp(rt->iface, rt->gw, packet, len);
		    else  iface_send_packet_by_arp(rt->iface, IP_dest_addr, packet, len);
	    } 
	    else 
	    {
		    icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
	    }
	}
}
