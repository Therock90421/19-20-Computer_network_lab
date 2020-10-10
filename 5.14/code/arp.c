#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void prepare_arp_packet(char* packet, iface_info_t *iface) {
	memcpy(packet + 6, iface->mac, ETH_ALEN);       //ether_shost is itself
	struct ether_header *tmp = (struct ether_header*)packet;
	tmp->ether_type = htons(ETH_P_ARP);             //ether_type is arp, 2 bytes
	struct ether_arp* ahdr = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	ahdr->arp_hrd = htons(0x01);                    //arp_header is 0x01, 2 bytes
	ahdr->arp_pro = htons(0x0800);                  //arp proto is 0x0800, 2 bytes
	ahdr->arp_hln = 6;                              //hardware address len(mac len) is 6, 1 byte
	ahdr->arp_pln = 4;                              //protocol address len(IP len) is 4, 1 byte
	memcpy(ahdr->arp_sha, iface->mac, ETH_ALEN);    //arp_sender mac is itself
	ahdr->arp_spa = htonl(iface->ip);               //arp_sender IP is itself, 4 bytes
	return;
}

void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
    char *packet = (char*)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	prepare_arp_packet(packet, iface);
	memset(packet, 0xff, ETH_ALEN);                  //ether_dhost is unknown
	struct ether_arp* ahdr = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	ahdr->arp_op = htons(ARPOP_REQUEST);             //arp_op is request, 2 bytes
	memset(ahdr->arp_tha, 0, ETH_ALEN);              //arp_target mac is zero
	ahdr->arp_tpa = htonl(dst_ip);                   //arp_target IP is dst_ip, 4 bytes
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
    char *packet = (char*)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	prepare_arp_packet(packet, iface);
	memcpy(packet, req_hdr->arp_sha, ETH_ALEN);       //ether_dhost is arp_request_sender's mac
	struct ether_arp* ahdr = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	ahdr->arp_op = htons(ARPOP_REPLY);                //arp_op is reply, 2 bytes
	memcpy(ahdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);//arp_target mac is arp_request_sender's mac
	ahdr->arp_tpa = req_hdr->arp_spa;                 //arp_target IP is arp_request_sender's IP, because we use IP from packet, so we don't need to htosl
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp* recv_ahdr = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	if (ntohl(recv_ahdr->arp_tpa) == iface->ip) 
	{       //receive a arp, and target IP is this port's ip
		if (ntohs(recv_ahdr->arp_op) == ARPOP_REQUEST) 
		{   //if arp_request
			arp_send_reply(iface, recv_ahdr);           //send arp_reply to this host
		} 
		if (ntohs(recv_ahdr->arp_op) == ARPOP_REPLY) 
		{   //if arp_reply
			arpcache_insert(ntohl(recv_ahdr->arp_spa), recv_ahdr->arp_sha);
		}
	} 
	else 
	{   //target IP is not this port
		free(packet);                                 
	}
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
