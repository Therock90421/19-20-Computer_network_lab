#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
    struct tcp_sock *tsk;
	struct tcp_timer *time, *q;
	list_for_each_entry_safe(time, q, &timer_list, list) {
		time->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if (time->timeout <= 0) {
			list_delete_entry(&time->list);
			tsk = timewait_to_tcp_sock(time);
			//list_delete_entry(&tsk->retrans_timer.list);
			if (! tsk->parent) //该sock为父sock，bind本地端口
				tcp_bind_unhash(tsk);
			if(tsk->state != TCP_CLOSED)
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


#define MAX_RETRANS 3
#define MIN_RETRANS_TIME 200000
#define TCP_RETRANS_SCAN_INTERVAL 10000
#define retrans_timer_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, retrans_timer))

static struct list_head retrans_timer_list;
void tcp_scan_retrans_timer_list()
{
	struct tcp_sock *tsk;
	struct tcp_timer *t, *q;
	list_for_each_entry_safe(t, q, &retrans_timer_list, list) {
		t->timeout -= TCP_RETRANS_SCAN_INTERVAL;
		tsk = retrans_timer_to_tcp_sock(t);
		if(t->timeout <=0){
			if(t->retrans_times>=MAX_RETRANS && tsk->state != TCP_CLOSED){
				list_delete_entry(&t->list);
				if (! tsk->parent)
					tcp_bind_unhash(tsk);
				wait_exit(tsk->wait_connect);
				wait_exit(tsk->wait_accept);
				wait_exit(tsk->wait_recv);
				wait_exit(tsk->wait_send);
				
				fprintf(stdout, "retrans 3 times failed, close TCP connection. \n");
				tcp_set_state(tsk, TCP_CLOSED);
				free_tcp_sock(tsk);
				send_buffer_free(); 
				exit(0);
			}
			else{
				t->retrans_times += 1;
				t->timeout = MIN_RETRANS_TIME * (2<<t->retrans_times);
				send_buffer_RETRAN_HEAD(tsk);
			}
		}
	}
}

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	struct tcp_timer *timer = &tsk->retrans_timer;

	timer->type = 1;
	timer->timeout = MIN_RETRANS_TIME;
	timer->retrans_times = 0;
	init_list_head(&timer->list);
	list_add_tail(&timer->list, &retrans_timer_list);

	tsk->ref_cnt += 1;
}

void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	struct tcp_timer *timer = &tsk->retrans_timer;

	timer->type = 1;
	timer->timeout = MIN_RETRANS_TIME;
	timer->retrans_times = 0;
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	struct tcp_timer *timer = &tsk->retrans_timer;
	list_delete_entry(&timer->list);
	free_tcp_sock(tsk);
}


void *tcp_retrans_timer_thread(void *arg)
{
	init_list_head(&retrans_timer_list);
	while(1){
		usleep(TCP_RETRANS_SCAN_INTERVAL);
		tcp_scan_retrans_timer_list();
	}
}






