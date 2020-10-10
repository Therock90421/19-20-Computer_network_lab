#ifndef __MOSPF_DAEMON_H__
#define __MOSPF_DAEMON_H__

#include "base.h"
#include "types.h"
#include "list.h"

void mospf_init();
void mospf_run();
void handle_mospf_packet(iface_info_t *iface, char *packet, int len);

void init_graph();

#define router_num 4
u32 router_list[router_num];
int graph[router_num][router_num];

#endif
