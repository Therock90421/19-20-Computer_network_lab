#include "mac.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here

	pthread_mutex_lock(&mac_port_map.lock);

	fprintf(stdout, "TODO: implement the lookup process here.\n");
	
	uint8_t hash_val = hash8((char*)mac, ETH_ALEN);
    mac_port_entry_t *mac_entry = NULL;
    int found = 0;
    list_for_each_entry(mac_entry, &mac_port_map.hash_table[hash_val], list)
	{
		found = 1;
        for(int i = 0; i < ETH_ALEN; i++)
		{
			if(mac_entry->mac[i] != mac[i])
			    found = 0;
		}
		if(found)
		{
			fprintf(stdout,"ATTENTION: mac port found. \n");
			mac_entry->visited = time(NULL);

			pthread_mutex_unlock(&mac_port_map.lock);
			return mac_entry->iface;
		}
	}
	fprintf(stdout,"ATTENTION: mac port not found. \n");
    pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{

	iface_info_t *IFACE = lookup_port(mac);
	//DONT USE lookup_port between lock and unlock!!!!!!
	if (IFACE) {
		(list_entry(IFACE, mac_port_entry_t, iface))->visited = time(NULL);
		fprintf(stdout, "ATTENTION: mac port found.\n");
		return;
	}
    pthread_mutex_lock(&mac_port_map.lock);
	uint8_t hash_val = hash8((char*)mac, ETH_ALEN);
	mac_port_entry_t *mac_entry = malloc(sizeof(mac_port_entry_t));
	for (int i = 0; i < ETH_ALEN; i++)
		mac_entry->mac[i] = mac[i];
	mac_entry->iface = iface;
	mac_entry->visited = time(NULL);
	
    list_add_tail(&mac_entry->list, &mac_port_map.hash_table[hash_val]);

    fprintf(stdout, "ATTENTION: mac port %s inserted.\n", iface->name);
	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	pthread_mutex_lock(&mac_port_map.lock);

	//fprintf(stdout, "TODO: implement the sweeping process here.\n");
    int number = 0;
    mac_port_entry_t *mac_entry, *q;
	for(int i = 0; i < HASH_8BITS; i++)
	{
		list_for_each_entry_safe(mac_entry, q, &mac_port_map.hash_table[i], list)
		{
			if(mac_entry->visited + MAC_PORT_TIMEOUT < time(NULL))
			{
				fprintf(stdout, "ATTENTION: mac port %s deleted.\n",mac_entry->iface->name);
				list_delete_entry(&mac_entry->list);
				free(mac_entry);
				number++;
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return number;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
