#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "packet.h"
#include "rtable.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;
pthread_mutex_t mospf_database_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);
	pthread_mutex_init(&mospf_database_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_db_thread(void *param);
void *calculating_rtable_thread(void *param);
void sending_mospf_lsu_func(void *param);
void calculating_rtable_func(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr;
	pthread_t db, rtable;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_db_thread, NULL);
	pthread_create(&rtable, NULL, calculating_rtable_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	int size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	while (1) 
	{
		pthread_mutex_lock(&mospf_lock);
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			char *packet = malloc(size * sizeof(char));
			memset(packet, 0, size);
			struct ether_header *ehdr = (struct ether_header*)packet;
			ehdr->ether_dhost[0] = 0x01;
			ehdr->ether_dhost[2] = 0x5e;
			ehdr->ether_dhost[5] = 0x05;
			memcpy(ehdr->ether_shost, iface->mac, ETH_ALEN);
			ehdr->ether_type = htons(ETH_P_IP);
			struct iphdr *ihdr = packet_to_ip_hdr(packet);
			ip_init_hdr(ihdr, iface->ip, MOSPF_ALLSPFRouters, size - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			struct mospf_hdr *mhdr = (struct mospf_hdr *)((char *)ihdr + IP_BASE_HDR_SIZE);
			struct mospf_hello *hello_message = (struct mospf_hello*)((char*)mhdr + MOSPF_HDR_SIZE);
			mospf_init_hello(hello_message, iface->mask);
			mospf_init_hdr(mhdr, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
			mhdr->checksum = mospf_checksum(mhdr);
			iface_send_packet(iface, packet, size);
		}
		pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	// fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1) 
	{
		iface_info_t *iface = NULL;
		pthread_mutex_lock(&mospf_lock);
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			mospf_nbr_t *nbr = NULL, *q;
			list_for_each_entry_safe(nbr, q, &iface->nbr_list, list) 
			{
				nbr->alive ++;
				if (nbr->alive >= MOSPF_NEIGHBOR_TIMEOUT) 
				{
					fprintf(stdout, "DEBUG: remove nbr %x.\n", nbr->nbr_id);
					list_delete_entry(&nbr->list);
					free(nbr);
					sending_mospf_lsu_func(NULL);
					calculating_rtable_func(NULL);
				}
			}
		}
		pthread_mutex_unlock(&mospf_lock);
		sleep(1);
	}
	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	struct iphdr *ihdr = packet_to_ip_hdr(packet);
	struct mospf_hdr *mhdr = (struct mospf_hdr *)((char *)ihdr + IP_HDR_SIZE(ihdr));
	pthread_mutex_lock(&mospf_lock);
	int find = 0;
	mospf_nbr_t *nbr = NULL;
	list_for_each_entry(nbr, &iface->nbr_list, list) 
	{
		if (nbr->nbr_id == ntohl(mhdr->rid)) 
		{
			find = 1;
			nbr->alive = 0;
			break;
		}
	}
	if (find == 0) 
	{
		fprintf(stdout, "DEBUG: receive new hello packet.\n");
		struct mospf_hello *hello_message = (struct mospf_hello*)((char*)mhdr + MOSPF_HDR_SIZE);
		mospf_nbr_t *new = (mospf_nbr_t*)malloc(sizeof(mospf_nbr_t));
		new->nbr_id = ntohl(mhdr->rid);
		new->nbr_ip = ntohl(ihdr->saddr);
		new->nbr_mask = ntohl(hello_message->mask);
		new->alive = 0;
		list_add_tail(&new->list, &iface->nbr_list);
		iface->num_nbr++;
		sending_mospf_lsu_func(NULL);
		calculating_rtable_func(NULL);
	}
	pthread_mutex_unlock(&mospf_lock);
}
void sending_mospf_lsu_func(void *param)
{
	int size_without_lsu_data = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE;
		int num = 0;
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			if (0 == iface->num_nbr) num++;
			else num += iface->num_nbr;
		}
		struct mospf_lsa *lsu_data = (struct mospf_lsa*)malloc(num * MOSPF_LSA_SIZE);
		int i = 0;
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			if (0 == iface->num_nbr) 
			{
				lsu_data[i].network = htonl(iface->ip & iface->mask);
				lsu_data[i].mask = htonl(iface->mask);
				lsu_data[i].rid = htonl(0);
				i++;
			} 
			else 
			{
				mospf_nbr_t *nbr = NULL;
				list_for_each_entry(nbr, &iface->nbr_list, list) 
				{
					lsu_data[i].network = htonl(nbr->nbr_ip & nbr->nbr_mask);
					lsu_data[i].mask = htonl(nbr->nbr_mask);
					lsu_data[i].rid = htonl(nbr->nbr_id);
					i++;
				}
			}
		}
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			if (iface->num_nbr) 
			{
				mospf_nbr_t *nbr = NULL;
				list_for_each_entry(nbr, &iface->nbr_list, list) 
				{
					int size = size_without_lsu_data + num * MOSPF_LSA_SIZE;
					char *packet = (char*)malloc(size * sizeof(char));
					memset(packet, 0, size);
					struct ether_header *ehdr = (struct ether_header*)packet;
					memcpy(ehdr->ether_shost, iface->mac, ETH_ALEN);
					ehdr->ether_type = htons(ETH_P_IP);
					struct iphdr *ihdr = packet_to_ip_hdr(packet);
					ip_init_hdr(ihdr, iface->ip, nbr->nbr_ip, size - ETHER_HDR_SIZE, IPPROTO_MOSPF);
					struct mospf_hdr *mhdr = (struct mospf_hdr *)((char *)ihdr + IP_BASE_HDR_SIZE);
					struct mospf_lsu *lsuhdr = (struct mospf_lsu*)((char*)mhdr + MOSPF_HDR_SIZE);
					mospf_init_lsu(lsuhdr, num);
					u32 *narray = (u32*)((char*)lsuhdr + MOSPF_LSU_SIZE);
					memcpy(narray, lsu_data, num * MOSPF_LSA_SIZE);
					//mospf_init_hdr(mhdr, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
					mospf_init_hdr(mhdr, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + num * MOSPF_LSA_SIZE, instance->router_id, instance->area_id);
					mhdr->checksum = mospf_checksum(mhdr);
					ip_send_packet(packet, size);
				}
			}
		}
		instance->sequence_num ++;
}
void *sending_mospf_lsu_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	//int size_without_lsu_data = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE;
	while (1) 
	{
		pthread_mutex_lock(&mospf_lock);
		sending_mospf_lsu_func(NULL);
		pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_LSUINT);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	pthread_mutex_lock(&mospf_database_lock);
	struct iphdr *ihdr = packet_to_ip_hdr(packet);
	struct mospf_hdr *mhdr = (struct mospf_hdr *)((char *)ihdr + IP_HDR_SIZE(ihdr));
	struct mospf_lsu *lsuhdr = (struct mospf_lsu*)((char*)mhdr + MOSPF_HDR_SIZE);
	int num = ntohl(lsuhdr->nadv);
	u32 *narray = (u32*)((char*)lsuhdr + MOSPF_LSU_SIZE);
	int find = 0;
	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) 
	{
		if (db_entry->rid == ntohl(mhdr->rid)) 
		{
			find = 1;
			if (db_entry->seq < ntohs(lsuhdr->seq)) 
			{
				db_entry->rid = ntohl(mhdr->rid);
				db_entry->seq = ntohs(lsuhdr->seq);
				db_entry->alive = 0;
				db_entry->nadv = num;
				db_entry->array = (struct mospf_lsa*)realloc(db_entry->array, num * MOSPF_LSA_SIZE);
				for (int i = 0; i < num; i++) {
					db_entry->array[i].network = ntohl(narray[i * 3]);
					db_entry->array[i].mask = ntohl(narray[i * 3 + 1]);
					db_entry->array[i].rid = ntohl(narray[i * 3 + 2]);
				}
			}
			calculating_rtable_func(NULL);
		}
	}
	if (find == 0) 
	{
		fprintf(stdout, "DEBUG: recieve new lsu packet, with %d lsa.\n", num);
		mospf_db_entry_t *new = (mospf_db_entry_t*)malloc(sizeof(mospf_db_entry_t));
		new->rid = ntohl(mhdr->rid);
		new->seq = ntohl(lsuhdr->seq);
		new->alive = 0;
		new->nadv = num;
		new->array = (struct mospf_lsa*)malloc(num * MOSPF_LSA_SIZE);
		for (int i = 0; i < num; i++) 
		{
			new->array[i].network = ntohl(narray[i * 3]);
			new->array[i].mask = ntohl(narray[i * 3 + 1]);
			new->array[i].rid = ntohl(narray[i * 3 + 2]);
		}
		list_add_tail(&new->list, &mospf_db);
		calculating_rtable_func(NULL);
	}
	pthread_mutex_unlock(&mospf_database_lock);
	if (--lsuhdr->ttl > 0) 
	{
		iface_info_t *iface_t = NULL;
		list_for_each_entry(iface_t, &instance->iface_list, list) 
		{
			if (iface_t->num_nbr && (iface->index != iface_t->index)) 
			{
				char *forward_packet = (char*)malloc(len);
				memcpy(forward_packet, packet, len);
				struct ether_header *ehdr = (struct ether_header*)forward_packet;
				struct iphdr *ihdr = packet_to_ip_hdr(forward_packet);
				struct mospf_hdr *mhdr = (struct mospf_hdr *)((char *)ihdr + IP_HDR_SIZE(ihdr));
				memcpy(ehdr->ether_shost, iface->mac, ETH_ALEN);
				mospf_nbr_t *nbr = NULL;
				list_for_each_entry(nbr, &iface_t->nbr_list, list) 
				{
					if (nbr->nbr_id == ntohl(mhdr->rid)) continue;
					mhdr->checksum = mospf_checksum(mhdr);
					ihdr->saddr = htonl(iface->ip);
					ihdr->daddr = htonl(nbr->nbr_ip);
					ihdr->checksum = ip_checksum(ihdr);
					ip_send_packet(forward_packet, len);
				}
			}
		}
	}
	if (find == 0) 
	{
		fprintf(stdout, "Route ID: %x",instance->router_id);
		fprintf(stdout, "\n");
		fprintf(stdout, "MOSPF Database entries:\n");
		list_for_each_entry(db_entry, &mospf_db, list) 
		{
			for (int i = 0; i < db_entry->nadv; i++) 
			{
				fprintf(stdout, IP_FMT"\t"IP_FMT"\t"IP_FMT"\t"IP_FMT"\n", \
						HOST_IP_FMT_STR(db_entry->rid), HOST_IP_FMT_STR(db_entry->array[i].network), \
						HOST_IP_FMT_STR(db_entry->array[i].mask), HOST_IP_FMT_STR(db_entry->array[i].rid));
			}
		}
	}
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

void *checking_db_thread(void *param) 
{
	while (1) 
	{
		pthread_mutex_lock(&mospf_database_lock);
		mospf_db_entry_t *db_entry = NULL, *q;
		list_for_each_entry_safe(db_entry, q, &mospf_db, list) 
		{
			db_entry->alive++;
			if (db_entry->alive >= MOSPF_DATABASE_TIMEOUT) 
			{
				rt_entry_t *rt_entry = NULL;
				rt_entry_t *q = longest_prefix_match(db_entry->rid);
				u32 gw = q->gw;
				list_for_each_entry_safe(rt_entry, q, &rtable, list) {
					if(0 != gw && rt_entry->gw == gw) 
					{
						fprintf(stdout, "DEBUG: remove rt_entry to %x.\n", rt_entry->dest);
						remove_rt_entry(rt_entry);
					}
				}
				list_delete_entry(&db_entry->list);
				//free(db_entry->array);
				free(db_entry);
				calculating_rtable_func(NULL);
			}
		}
		pthread_mutex_unlock(&mospf_database_lock);
		sleep(1);
	}
	return NULL;
}

void init_graph() 
{
	memset(router_list, 0, sizeof(router_list));
	router_list[0] = instance->router_id;
	memset(graph, 0, sizeof(graph));
	iface_info_t *iface = NULL;
	int i = 1;
		list_for_each_entry(iface, &instance->iface_list, list) 
		{
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) 
			{
				router_list[i] = nbr->nbr_id;
				graph[0][i] = 1;
				graph[i][0] = 1;
				i++;
			}
		}
}

int min_dist(u8 *dist, int *visited) 
{
	int res = 0;
	int _min = INT8_MAX;
	for (int i = 0; i < router_num; i++) 
	{
		if (!visited[i]) continue;
		for (int j = 0; j < router_num; j++) 
		{
			if (0 == visited[j] && graph[i][j] > 0 && \
					graph[i][j] + dist[i] < _min) 
			{
				_min = graph[i][j] + dist[i];
				res = j;
			}
		}
	}
	dist[res] = _min;
	return res;
}

void Dijkstra(int *prev) 
{
	u8 dist[router_num];
	memset(dist, UINT8_MAX, router_num);
	int visited[router_num] = {0};
	dist[0] = 0;
	visited[0] = 1;
	for (int i = 0; i < router_num; i++) 
	{
		int u = min_dist(dist, visited);
		visited[u] = 1;
		for (int j = 0; j < router_num; j++) 
		{
			if (0 == visited[j] && graph[u][j] > 0 && \
					dist[u] + graph[u][j] < dist[j]) 
			{
				dist[j] = dist[u] + graph[u][j];
				prev[j] = u;
			}
		}
	}
}
void calculating_rtable_func(void *param)
{
	fprintf(stdout, "DEBUG: calculating rtable.\n");
		init_graph();
		int i = 1;

		mospf_db_entry_t *db_entry = NULL;
		list_for_each_entry(db_entry, &mospf_db, list) 
		{
			for (i = 1; i < router_num; i++) 
			{
				if (router_list[i] == db_entry->rid || !router_list[i]) break;
			}
			if (!router_list[i]) router_list[i] = db_entry->rid;
		}
		// Fill the edge matrix.
		list_for_each_entry(db_entry, &mospf_db, list) 
		{
			int t1 = 0;
			while (router_list[t1] != db_entry->rid && t1 < router_num) 
			{
				t1++;
			}
			if (router_num == t1) continue;
			for (i = 0; i < db_entry->nadv; i++) 
			{
				if (0 == db_entry->array[i].rid) continue;
				int t2 = 0;
				while (router_list[t2] != db_entry->array[i].rid && t2 < router_num) 
				{
					t2++;
				}
				if (router_num == t2) continue;
				graph[t1][t2] = 1;
				graph[t2][t1] = 1;
			}
		}
		//pthread_mutex_unlock(&mospf_database_lock);
		int prev[router_num] = {0};
		prev[0] = -1;
		Dijkstra(prev);
		for (int t1 = 1; t1 < router_num; t1++) 
		{
			if (prev[t1] != 0 && prev[prev[t1]] != 0) 
			{
				prev[t1] = prev[prev[t1]];
				t1--;
			}
		}
		rt_entry_t *rt_entry = NULL;
		list_for_each_entry(rt_entry, &rtable, list) 
		{
			if (0 == rt_entry->gw) rt_entry->valid = 1;
			else rt_entry->valid = 0;
		}
		for (int t1 = 1; t1 < router_num; t1++) 
		{
			u32 rid = router_list[t1];
			u32 gw_rid = (0 == prev[t1])?router_list[t1] : router_list[prev[t1]];
			iface_info_t *iface = NULL;
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(iface, &instance->iface_list, list) 
			{
				int found = 0;
				list_for_each_entry(nbr, &iface->nbr_list, list) 
				{
					if (nbr->nbr_id == gw_rid) 
					{
						found = 1;
						break;
					}
				}
				if (found) break;
			}
			mospf_db_entry_t *db_entry = NULL;
			list_for_each_entry(db_entry, &mospf_db, list) 
			{
				if (db_entry->rid == rid) 
				{
					for(int t1 = 0; t1 < db_entry->nadv; t1++) 
					{
						rt_entry_t *rt_entry = NULL;
						int found = 0;
						list_for_each_entry(rt_entry, &rtable, list) 
						{
							if (rt_entry->dest == db_entry->array[t1].network) 
							{
								found = 1;
								break;
							}
						}
						//if (0 == found) {
						if (0 == found) 
						{
							if(db_entry->array[t1].mask == 0) continue;
							rt_entry_t *new = new_rt_entry(db_entry->array[t1].network, \
									db_entry->array[t1].mask, nbr->nbr_ip, iface);
							new->valid = 1;
							add_rt_entry(new);
						} 
						else if (nbr->nbr_ip != rt_entry->gw && 0 == rt_entry->valid) 
						{
							remove_rt_entry(rt_entry);
							if(db_entry->array[t1].mask == 0) continue;
							rt_entry_t *new = new_rt_entry(db_entry->array[t1].network, \
									db_entry->array[t1].mask, nbr->nbr_ip, iface);
							new->valid = 1;
							add_rt_entry(new);
						} else rt_entry->valid = 1;
					}
				}
			}
		}
		print_rtable();
}
void *calculating_rtable_thread(void *param) 
{
	while (1) 
	{
		fprintf(stdout, "DEBUG: calculating rtable.\n");
		int i = 1;
		pthread_mutex_lock(&mospf_lock);
		init_graph();
		pthread_mutex_unlock(&mospf_lock);
		pthread_mutex_lock(&mospf_database_lock);
		mospf_db_entry_t *db_entry = NULL;
		list_for_each_entry(db_entry, &mospf_db, list) 
		{
			for (i = 1; i < router_num; i++) 
			{
				if (router_list[i] == db_entry->rid || !router_list[i]) break;
			}
			if (!router_list[i]) router_list[i] = db_entry->rid;
		}
		// Fill the edge matrix.
		list_for_each_entry(db_entry, &mospf_db, list) 
		{
			int t1 = 0;
			while (router_list[t1] != db_entry->rid && t1 < router_num) 
			{
				t1++;
			}
			if (router_num == t1) continue;
			for (i = 0; i < db_entry->nadv; i++) 
			{
				if (0 == db_entry->array[i].rid) continue;
				int t2 = 0;
				while (router_list[t2] != db_entry->array[i].rid && t2 < router_num) 
				{
					t2++;
				}
				if (router_num == t2) continue;
				graph[t1][t2] = 1;
				graph[t2][t1] = 1;
			}
		}
		pthread_mutex_unlock(&mospf_database_lock);
		int prev[router_num] = {0};
		prev[0] = -1;
		Dijkstra(prev);
		for (int t1 = 1; t1 < router_num; t1++) 
		{
			if (prev[t1] != 0 && prev[prev[t1]] != 0) 
			{
				prev[t1] = prev[prev[t1]];
				t1--;
			}
		}
		rt_entry_t *rt_entry = NULL;
		list_for_each_entry(rt_entry, &rtable, list) 
		{
			if (0 == rt_entry->gw) rt_entry->valid = 1;
			else rt_entry->valid = 0;
		}
		for (int t1 = 1; t1 < router_num; t1++) 
		{
			u32 rid = router_list[t1];
			u32 gw_rid = (0 == prev[t1])?router_list[t1] : router_list[prev[t1]];
			iface_info_t *iface = NULL;
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(iface, &instance->iface_list, list) {
				int found = 0;
				list_for_each_entry(nbr, &iface->nbr_list, list) 
				{
					if (nbr->nbr_id == gw_rid) 
					{
						found = 1;
						break;
					}
				}
				if (found) break;
			}
			mospf_db_entry_t *db_entry = NULL;
			list_for_each_entry(db_entry, &mospf_db, list) 
			{
				if (db_entry->rid == rid) 
				{
					for(int t1 = 0; t1 < db_entry->nadv; t1++) 
					{
						rt_entry_t *rt_entry = NULL;
						int found = 0;
						list_for_each_entry(rt_entry, &rtable, list) 
						{
							if (rt_entry->dest == db_entry->array[t1].network) 
							{
								found = 1;
								break;
							}
						}
						if (0 == found) 
						{
							if(db_entry->array[t1].mask == 0) continue;
							rt_entry_t *new = new_rt_entry(db_entry->array[t1].network, \
									db_entry->array[t1].mask, nbr->nbr_ip, iface);
							new->valid = 1;
							add_rt_entry(new);
						} 
						else if (nbr->nbr_ip != rt_entry->gw && 0 == rt_entry->valid) 
						{
							remove_rt_entry(rt_entry);
							if(db_entry->array[t1].mask == 0) continue;
							rt_entry_t *new = new_rt_entry(db_entry->array[t1].network, \
									db_entry->array[t1].mask, nbr->nbr_ip, iface);
							new->valid = 1;
							add_rt_entry(new);
						} else rt_entry->valid = 1;
					}
				}
			}
		}

		print_rtable();
		sleep(10);
	}
	return NULL;
}
