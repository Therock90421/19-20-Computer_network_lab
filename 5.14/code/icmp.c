#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	//struct ether_header *in_pkt_etherhead = (struct ether_header*)in_pkt;
	struct iphdr *in_pkt_IPhead = packet_to_ip_hdr(in_pkt);
	int pkt_len;
	if (type == ICMP_ECHOREPLY) pkt_len = len;
	else pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + IP_HDR_SIZE(in_pkt_IPhead) + ICMP_HDR_SIZE + 8;
    //ATTENTION: PING's packet is a standard packet, it's IP head's size is 20(IP_BASE_HDR_SIZE)
	char *packet = (char*)malloc(pkt_len * sizeof(char));
	struct ether_header *ehdr = (struct ether_header*)packet;
	//memcpy(ehdr->ether_dhost, in_pkt_etherhead->ether_shost, ETH_ALEN);
	//memcpy(ehdr->ether_shost, in_pkt_etherhead->ether_dhost, ETH_ALEN);
	ehdr->ether_type = htons(ETH_P_IP);

	struct iphdr *packet_IPhead = packet_to_ip_hdr(packet);
	rt_entry_t *rt = longest_prefix_match(ntohl(in_pkt_IPhead->saddr));
	ip_init_hdr(packet_IPhead, rt->iface->ip, ntohl(in_pkt_IPhead->saddr), pkt_len - ETHER_HDR_SIZE, 1);
    //To tell the sender host this ICMP is create by rt->iface->ip
	struct icmphdr *packet_IChead = (struct icmphdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	packet_IChead->type = type;
	packet_IChead->code = code;
	int packet_Rest_begin = ETHER_HDR_SIZE + IP_HDR_SIZE(packet_IPhead) + 4;
	if (type == ICMP_ECHOREPLY) 
	{   //reply for ping
		memcpy(packet + packet_Rest_begin, in_pkt + packet_Rest_begin, pkt_len - packet_Rest_begin);
	} 
	else 
	{
		memset(packet + packet_Rest_begin, 0, 4);
		memcpy(packet + packet_Rest_begin + 4, in_pkt + ETHER_HDR_SIZE, IP_HDR_SIZE(in_pkt_IPhead) + 8);
	}
	packet_IChead->checksum = icmp_checksum(packet_IChead, pkt_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE);
	//ICMP packet's IP head's size will always be IP_BASE_HDR_SIZE
	ip_send_packet(packet, pkt_len);
}
