#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

void tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if(less_than_32b(cb->seq, tsk->rcv_nxt))
	{
		return;
	}
	ofo_packet_enqueue(tsk, cb, packet); 
	ofo_packet_dequeue(tsk); 
	tsk->snd_una = (greater_than_32b(cb->ack, tsk->snd_una))?cb->ack :tsk->snd_una;
	//tcp_send_control_packet(tsk, TCP_ACK);
	//发包之前，打开重传计时器
	tcp_set_retrans_timer(tsk);
	tcp_send_data(tsk, "data_recv!",sizeof("data_recv!"));
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    if(!tsk)
		return;
	//首先，CLOSED、LISTEN、SYN_SENT三个状态下，都不会收到新的数据，所以不用判定窗口
    //如果状态是TCP_CLOSED
	if(tsk->state == TCP_CLOSED)
	{
		//tcp_state_closed_handle_packet(tsk, cb, packet);//tsk die,with RST insde it
		tcp_send_reset(cb);
		return;
	}
	//如果状态是TCP_LISTEN
	if(tsk->state == TCP_LISTEN)
	{
		//tcp_state_listen_handle_packet(tsk, cb, packet);//has ack inside it
		//处于监听状态下，如果监听对象不存在，就返回；
	    //               如果收到的包不是SYN，就返回RST
    	if(tsk==NULL)
		{
	    	tcp_send_reset(cb);
		    return;
	    }
	    else if((cb->flags & TCP_SYN) == 0)
		{
		    if(cb->flags & TCP_RST)
			    return;
	    	else{
		    	tcp_send_reset(cb);
			    return;
    		}
	    }

	    //如果收到的包是SYN，就准备建立连接
    	//新建一个子sock，初始化好对应的数据，并把它插入父sock的listen_sock上
		fprintf(stdout,"==========================================\n");
		fprintf(stdout,"ATTENTION: NEW CONNECTION REQUEST ARRIVES.\n");
		fprintf(stdout,"           CREATE NEW CHILD SOCKET.\n");
		fprintf(stdout,"==========================================\n");
    	struct tcp_sock *child_sk = alloc_tcp_sock();
    	child_sk->sk_sip   = cb->daddr;
	    child_sk->sk_sport = cb->dport;
	    child_sk->sk_dip   = cb->saddr;
	    child_sk->sk_dport = cb->sport;
	    child_sk->iss = tcp_new_iss();
	    //csk->snd_una = csk->iss; //here!
	    child_sk->snd_nxt = child_sk->iss;
	    child_sk->rcv_nxt = cb->seq + 1;
	    child_sk->parent = tsk;
	    list_add_tail(&child_sk->list, &tsk->listen_queue);//list_add_tail(&csk->list, &csk->listen_queue);
	    //修改子sock的状态为SYN_RECV，发送SYN|ACK报文，并把子sock添加到tcp_established_sock_table
	    tcp_set_state(child_sk, TCP_SYN_RECV);
	    //发包之前，打开重传计时器
		tcp_set_retrans_timer(child_sk);
	    tcp_send_control_packet(child_sk, TCP_SYN|TCP_ACK);
	    tcp_hash(child_sk);
	    	return;
	}
    //如果状态是TCP_SYN_SENT
	if(tsk->state == TCP_SYN_SENT)
	{
		//tcp_state_syn_sent_handle_packet(tsk, cb, packet);//has ack inside it
		//正常情况下，会收到SYN|ACK的包，修改rcv_nxt和snd_una
	    if( (cb->flags & (TCP_SYN|TCP_ACK)) == (TCP_SYN|TCP_ACK) )
	    {
		    tsk->rcv_nxt = cb->seq + 1;
		    tsk->snd_una = cb->ack;
			///////////////////////////////////////////
		    send_buffer_ACK(tsk, cb->ack);
		    tcp_unset_retrans_timer(tsk);
	    //修改状态为TCP_ESTABLISHED，发送ACK报文，随后唤醒tcp_sock_connect	
		    tcp_set_state(tsk, TCP_ESTABLISHED);
	    	tcp_send_control_packet(tsk, TCP_ACK);
		    wake_up(tsk->wait_connect);
	    }
	    else 
	    {//异常情况下，就直接返回RST包
		    tcp_send_reset(cb);
		    fprintf(stdout,"Recv packet ERROR, link down. \n");
		    exit(0);
	    }
		return;
	}
	//查看收到的包是不是RST，如果是就关闭连接，释放tsk
	if(cb->flags & TCP_RST )
	{
		tcp_sock_close(tsk);
		free(tsk);
		return;
	}

    //查看收到的包是不是SYN，如果是，说明是一个非法的SYN，另一端发生混乱，就发送RST，关闭连接，释放tsk
    if(cb->flags & TCP_SYN)
	{
		tcp_send_reset(cb);
		tcp_sock_close(tsk);
		return;
	}
    //如果当前状态为SYN_RECV
	if(tsk->state == TCP_SYN_RECV)
	{
		//tcp_state_syn_recv_handle_packet(tsk, cb, packet); //don't need send ack
		//正常情况下，收到的包是ACK
	    if(cb->flags & TCP_ACK)
		{
		    struct tcp_sock *csk = tsk, *parent_tsk = csk->parent;
            //将子sock从父sock的listen_queue去除，加入到accept_queue
		    tcp_sock_accept_enqueue(csk);
	
		    csk->rcv_nxt = cb->seq;//注意！从对端发来的ACK报文不消耗序号，所以不需要+1
		    tsk->snd_una = cb->ack;
			//修改send_buffer，
		    send_buffer_ACK(tsk, cb->ack);
		    tcp_unset_retrans_timer(tsk);

		    //设置子sock的状态为TCP_ESTABLISHED
		    tcp_set_state(csk,        TCP_ESTABLISHED);
		    //唤醒父sock的tcp_sock_accept
		    wake_up(parent_tsk->wait_accept);
		    //tcp_send_control_packet(tsk, TCP_ACK);
	    }
		return;
	}
	//如果当前状态为ESTABLISHED，调用tcp_update_window_safe更新窗口
	else if(tsk->state == TCP_ESTABLISHED && (cb->flags & TCP_FIN)==0 )
	{
		if(cb->pl_len==0 || strcmp(cb->payload,"data_recv!")==0){ //just an ACK packet
				tsk->snd_una = cb->ack;
				tsk->rcv_nxt = cb->seq +1;
				tcp_update_window_safe(tsk, cb);
				////////////////////////////////////////////
				send_buffer_ACK(tsk, cb->ack);
				tcp_update_retrans_timer(tsk);
				wake_up(tsk->wait_send);
				return;
			}
			else{ //packet with data
				tcp_recv_data(tsk, cb, packet);
				return;
			}
	}
	//如果当前状态不是CLOSED,LISTEN,SYN_SENT,SYN_RECV,ESTABLISHED（也就是处于即将关闭连接的状态）
	//如果FIN不为1
	else if((cb->flags & TCP_FIN) ==0)
	{
		switch(tsk->state)
		{
			case TCP_FIN_WAIT_1:
		        //////////////////////////////////////
				send_buffer_ACK(tsk, cb->ack);
				tcp_unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
				return;
			case TCP_CLOSING:
			    //////////////////////////////////////
				send_buffer_ACK(tsk, cb->ack);
				tcp_unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
				tcp_unhash(tsk);
				return;
			case TCP_LAST_ACK:
			    //////////////////////////////////////
				send_buffer_ACK(tsk, cb->ack);
				tcp_unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_CLOSED);
				//HERE!
				tcp_unhash(tsk);
				fprintf(stdout,"TCP connection down. \n");
				return;
			default:
				break;
		}
	}
	//如果FIN为1
	if(cb->flags & TCP_FIN)
	{
		switch(tsk->state)
		{
			case TCP_ESTABLISHED:
				tsk->rcv_nxt = cb->seq+1;
				wait_exit(tsk->wait_recv);
				wait_exit(tsk->wait_send);
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
				tcp_send_control_packet(tsk, TCP_ACK);
				return;
			case TCP_FIN_WAIT_1:
				tcp_set_state(tsk, TCP_CLOSING);
				tcp_send_control_packet(tsk, TCP_ACK);
				return;
			case TCP_FIN_WAIT_2:
				tsk->rcv_nxt = cb->seq+1;
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_unhash(tsk);
				return;
			default:
				break;
		}
	}
    //最后补充需要发送ACK的场合
	tcp_send_control_packet(tsk, TCP_ACK);
	return;
}
