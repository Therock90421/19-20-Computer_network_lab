#include "ip.h"
#include "icmp.h"
#include "packet.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

u32 get_next_hop(rt_entry_t *entry, u32 dst)
{
	if (entry->gw)
		return entry->gw;
	else
		return dst;
}

void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->ttl <= 1) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return ;
	}

	ip->ttl -= 1;
	ip->checksum = ip_checksum(ip);

	rt_entry_t *entry = longest_prefix_match(ip_dst);
	if (!entry) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return ;
	}

	u32 next_hop = get_next_hop(entry, ip_dst);

	iface_info_t *iface = entry->iface;

	iface_send_packet_by_arp(iface, next_hop, packet, len);
}
// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.

void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}
