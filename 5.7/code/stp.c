#include "stp.h"

#include "base.h"
#include "ether.h"
#include "utils.h"
#include "types.h"
#include "packet.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>

stp_t *stp;

const u8 eth_stp_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

static bool stp_is_root_switch(stp_t *stp)
{
	return stp->designated_root == stp->switch_id;
}

static bool stp_port_is_designated(stp_port_t *p)
{
	return p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id;
}

static const char *stp_port_state(stp_port_t *p)
{
	if (p->stp->root_port && \
			p->port_id == p->stp->root_port->port_id)
		return "ROOT";
	else if (p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id)
		return "DESIGNATED";
	else
		return "ALTERNATE";
}

static void stp_port_send_packet(stp_port_t *p, void *stp_msg, int msg_len)
{
	int pkt_len = ETHER_HDR_SIZE + LLC_HDR_SIZE + msg_len;
	char *pkt = malloc(pkt_len);

	// ethernet header
	struct ether_header *eth = (struct ether_header *)pkt;
	memcpy(eth->ether_dhost, eth_stp_addr, 6);
	memcpy(eth->ether_shost, p->iface->mac, 6);
	eth->ether_type = htons(pkt_len - ETHER_HDR_SIZE);

	// LLC header
	struct llc_header *llc = (struct llc_header *)(pkt + ETHER_HDR_SIZE);
	llc->llc_dsap = LLC_DSAP_SNAP;
	llc->llc_ssap = LLC_SSAP_SNAP;
	llc->llc_cntl = LLC_CNTL_SNAP;

	memcpy(pkt + ETHER_HDR_SIZE + LLC_HDR_SIZE, stp_msg, msg_len);

	iface_send_packet(p->iface, pkt, pkt_len);
}

static void stp_port_send_config(stp_port_t *p)
{
	stp_t *stp = p->stp;
	bool is_root = stp_is_root_switch(stp);
	if (!is_root && !stp->root_port) {
		return;
	}

	struct stp_config config;
	memset(&config, 0, sizeof(config));
	config.header.proto_id = htons(STP_PROTOCOL_ID);
	config.header.version = STP_PROTOCOL_VERSION;
	config.header.msg_type = STP_TYPE_CONFIG;
	config.flags = 0;
	config.root_id = htonll(stp->designated_root);
	config.root_path_cost = htonl(stp->root_path_cost);
	config.switch_id = htonll(stp->switch_id);
	config.port_id = htons(p->port_id);
	config.msg_age = htons(0);
	config.max_age = htons(STP_MAX_AGE);
	config.hello_time = htons(STP_HELLO_TIME);
	config.fwd_delay = htons(STP_FWD_DELAY);

	// log(DEBUG, "port %s send config packet.", p->port_name);
	stp_port_send_packet(p, &config, sizeof(config));
}

static void stp_send_config(stp_t *stp)
{
	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) {
			stp_port_send_config(p);
		}
	}
}

static void stp_handle_hello_timeout(void *arg)
{
	// log(DEBUG, "hello timer expired, now = %llx.", time_tick_now());

	stp_t *stp = arg;
	stp_send_config(stp);
	stp_start_timer(&stp->hello_timer, time_tick_now());
}

static void stp_port_init(stp_port_t *p)
{
	stp_t *stp = p->stp;

	p->designated_root = stp->designated_root;
	p->designated_switch = stp->switch_id;
	p->designated_port = p->port_id;
	p->designated_cost = stp->root_path_cost;
}

void *stp_timer_routine(void *arg)
{
	while (true) {
		long long int now = time_tick_now();

		pthread_mutex_lock(&stp->lock);

		stp_timer_run_once(now);

		pthread_mutex_unlock(&stp->lock);

		usleep(100);
	}

	return NULL;
}

static void stp_handle_config_packet(stp_t *stp, stp_port_t *p,
		struct stp_config *config)
{
	// TODO: handle config packet here
	//fprintf(stdout, "TODO: handle config packet here.\n");
	int priority = 0;
    //compare priority between configs
    if( p->designated_root !=  ntohll(config->root_id) )
		priority = ( p->designated_root > ntohll(config->root_id) )? 1:0;
	else if( p->designated_cost !=  ntohl(config->root_path_cost) )
		priority = ( p->designated_cost > ntohl(config->root_path_cost) )? 1:0;
	else if (p->designated_switch != ntohll(config->switch_id) )
		priority = ((p->designated_switch &0xffffffffffff)> (ntohll(config->switch_id) &0xffffffffffff))? 1:0;
	else if(p->designated_port != ntohs(config->port_id) )
		priority = ((p->designated_port &0xff)> (ntohs(config->port_id) &0xff))? 1:0;
	
	if (priority == 1) {//Lastest received config's priority is higher

		// Replace config for this port
		// This case proves that this port is designated_port
		p->designated_root   = ntohll(config->root_id);
		p->designated_cost   = ntohl (config->root_path_cost);
		p->designated_switch = ntohll(config->switch_id);
		p->designated_port   = ntohs (config->port_id);
		
	
		
		int root_num = 0;
		int find_root = 1;
		// To find a root_port.
		for (int i = 0; i < stp->nports; i++) {
			//If one port is possiblely a root port, it is non-designated
			if (!stp_port_is_designated(&(stp->ports[i]))) {
				root_num = i;
				break;
			}
			// Not found root_port.
			if (i == stp->nports - 1) find_root = 0;
		}
		//After above, we find the smallest non-designated port
		for (int i = root_num + 1; i < stp->nports; i++) {
			if (stp_port_is_designated(&(stp->ports[i]))) continue;
			int priority = 1;
            if(stp->ports[i].designated_root !=  stp->ports[root_num].designated_root )
	    	    priority = ( stp->ports[i].designated_root > stp->ports[root_num].designated_root )? 0:1;
	        else if( stp->ports[i].designated_cost !=  stp->ports[root_num].designated_cost )
		        priority = ( stp->ports[i].designated_cost > stp->ports[root_num].designated_cost )? 0:1;
	        else if (stp->ports[i].designated_switch != stp->ports[root_num].designated_switch )
	            //fitst bit of switch is 1, so if compare directly, answer will be opposite
				priority = ((stp->ports[i].designated_switch &0xffffffffffff) > (stp->ports[root_num].designated_switch &0xffffffffffff))? 0:1;
        	else if(stp->ports[i].designated_port != stp->ports[root_num].designated_port )
	        	priority = ((p->designated_port &0xff)> (stp->ports[root_num].designated_port &0xff))? 0:1;

			if (priority) root_num = i;
		}
		//After above, we find the root_port(if exists)
		if (!find_root) {
			// This is root node.
			stp->root_port = NULL;
			stp->designated_root = stp->switch_id;
			stp->root_path_cost = 0;
		} else {
			stp->root_port = &(stp->ports[root_num]);
			stp->designated_root = stp->root_port->designated_root;
			stp->root_path_cost = stp->root_port->designated_cost + stp->root_port->path_cost;
		}
		// Replace config for this node's port
		for (int i = 0; i < stp->nports; i++) {
			if (stp_port_is_designated(&(stp->ports[i]))) {
				stp->ports[i].designated_root = stp->designated_root;
				stp->ports[i].designated_cost = stp->root_path_cost;
			} 
			//If one net's non-designated port's designated_cost is higher than this port
			//'s node's root_path_cost, that net should change its designated port to this node's port
			/*else if (stp->root_path_cost < stp->ports[i].designated_cost) {*/
			else if((stp->root_path_cost < stp->ports[i].designated_cost)|| (stp->root_path_cost==stp->ports[i].designated_cost)&
               (stp->switch_id < stp->ports[i].designated_switch)  || (stp->root_path_cost==stp->ports[i].designated_cost)&
               (stp->switch_id==stp->ports[i].designated_switch) & (stp->ports[i].port_id==stp->ports[i].designated_port)){
			//this judge can be added like this:
             // (stp->root_path_cost < stp->ports[i].designated_cost)|| (stp->root_path_cost==stp->ports[i].designated_cost)&
             //  (stp->switch_id < stp->ports[i].designated_switch)  || (stp->root_path_cost==stp->ports[i].designated_cost)&
             //  (stp->switch_id==stp->ports[i].designated_switch)   &  (stp->ports[i].port_id==stp->ports[i].designated_port)
             //but it is too complex, I ignored that XD
	
				stp->ports[i].designated_switch = stp->switch_id;
				stp->ports[i].designated_port = stp->ports[i].port_id;
				stp->ports[i].designated_root = stp->designated_root;
				stp->ports[i].designated_cost = stp->root_path_cost;
			}
		}
		//If node lose its root character
		if (!stp_is_root_switch(stp))
			stp_stop_timer(&(stp->hello_timer));
		//Send updated config message from every desginated port
		for (int i = 0; i < stp->nports; i++)
			if (stp_port_is_designated(&(stp->ports[i])))
				stp_port_send_config(&(stp->ports[i]));
	} else {
		stp_port_send_config(p);
	}
}

static void *stp_dump_state(void *arg)
{
#define get_switch_id(switch_id) (int)(switch_id & 0xFFFF)
#define get_port_id(port_id) (int)(port_id & 0xFF)

	pthread_mutex_lock(&stp->lock);

	bool is_root = stp_is_root_switch(stp);
	if (is_root) {
		log(INFO, "this switch is root."); 
	}
	else {
		log(INFO, "non-root switch, designated root: %04x, root path cost: %d.", \
				get_switch_id(stp->designated_root), stp->root_path_cost);
	}

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		log(INFO, "port id: %02d, role: %s.", get_port_id(p->port_id), \
				stp_port_state(p));
		log(INFO, "\tdesignated ->root: %04x, ->switch: %04x, " \
				"->port: %02d, ->cost: %d.", \
				get_switch_id(p->designated_root), \
				get_switch_id(p->designated_switch), \
				get_port_id(p->designated_port), \
				p->designated_cost);
	}

	pthread_mutex_unlock(&stp->lock);

	exit(0);
}

static void stp_handle_signal(int signal)
{
	if (signal == SIGTERM) {
		log(DEBUG, "received SIGTERM, terminate this program.");
		
		pthread_t pid;
		pthread_create(&pid, NULL, stp_dump_state, NULL);
	}
}

void stp_init(struct list_head *iface_list)
{
	stp = malloc(sizeof(*stp));

	// set switch ID
	u64 mac_addr = 0;
	iface_info_t *iface = list_entry(iface_list->next, iface_info_t, list);
	for (int i = 0; i < sizeof(iface->mac); i++) {
		mac_addr <<= 8;
		mac_addr += iface->mac[i];
	}
	stp->switch_id = mac_addr | ((u64) STP_BRIDGE_PRIORITY << 48);

	stp->designated_root = stp->switch_id;
	stp->root_path_cost = 0;
	stp->root_port = NULL;

	stp_init_timer(&stp->hello_timer, STP_HELLO_TIME, \
			stp_handle_hello_timeout, (void *)stp);

	stp_start_timer(&stp->hello_timer, time_tick_now());

	stp->nports = 0;
	list_for_each_entry(iface, iface_list, list) {
		stp_port_t *p = &stp->ports[stp->nports];

		p->stp = stp;
		p->port_id = (STP_PORT_PRIORITY << 8) | (stp->nports + 1);
		p->port_name = strdup(iface->name);
		p->iface = iface;
		p->path_cost = 1;

		stp_port_init(p);

		// store stp port in iface for efficient access
		iface->port = p;

		stp->nports += 1;
	}

	pthread_mutex_init(&stp->lock, NULL);
	pthread_create(&stp->timer_thread, NULL, stp_timer_routine, NULL);

	signal(SIGTERM, stp_handle_signal);
}

void stp_destroy()
{
	pthread_kill(stp->timer_thread, SIGKILL);

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *port = &stp->ports[i];
		port->iface->port = NULL;
		free(port->port_name);
	}

	free(stp);
}

void stp_port_handle_packet(stp_port_t *p, char *packet, int pkt_len)
{
	stp_t *stp = p->stp;

	pthread_mutex_lock(&stp->lock);
	
	// protocol insanity check is omitted
	struct stp_header *header = (struct stp_header *)(packet + ETHER_HDR_SIZE + LLC_HDR_SIZE);

	if (header->msg_type == STP_TYPE_CONFIG) {
		stp_handle_config_packet(stp, p, (struct stp_config *)header);
	}
	else if (header->msg_type == STP_TYPE_TCN) {
		log(ERROR, "TCN packet is not supported in this lab.");
	}
	else {
		log(ERROR, "received invalid STP packet.");
	}

	pthread_mutex_unlock(&stp->lock);
}
