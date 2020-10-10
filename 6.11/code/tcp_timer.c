#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    struct tcp_sock *tsk;
	struct tcp_timer *time, *q;
	list_for_each_entry_safe(time, q, &timer_list, list) {
		time->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if (time->timeout <= 0) {
			list_delete_entry(&time->list);
			tsk = timewait_to_tcp_sock(time);
			if (! tsk->parent) //该sock为父sock，bind本地端口
				tcp_bind_unhash(tsk);
			tcp_set_state(tsk, TCP_CLOSED);
			free_tcp_sock(tsk);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    struct tcp_timer *timer = &tsk->timewait;
	timer->type = 0;
	timer->timeout = TCP_TIMEWAIT_TIMEOUT;
	list_add_tail(&timer->list, &timer_list);
	tsk->ref_cnt += 1;
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
