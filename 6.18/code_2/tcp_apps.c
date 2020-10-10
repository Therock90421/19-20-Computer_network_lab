#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char rbuf[1001];
	char wbuf[1024];
	int rlen = 0;
	int time = 0;
    int *fd1;
	fd1 = open("server-output.dat",O_RDWR|O_CREAT|O_APPEND);
	while (1) {
		rlen = tcp_sock_read(csk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			//sprintf(wbuf, "server echoes: %s", rbuf);
			sprintf(wbuf, "server echoes: %d", time);
			time++;
            write(fd1,rbuf,rlen);
			if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
				log(DEBUG, "tcp_sock_write return negative value, something goes wrong.");
				exit(1);
			}
		}
		else {
			fprintf(stdout,"%d \n" , rlen);
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	
    fprintf(stdout,"haoo");
    FILE *fd = fopen("client-input.dat", "r");
	//FILE *fd = fopen("client-input.dat", "r");
	char x;
	int m;
	char *wbuf = (char *)malloc(10000000*sizeof(char));
	//char *wbuf = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	//int wlen = strlen(wbuf);
	while((x = fgetc(fd))!= EOF)
    { 
        wbuf[m] = x;
        m++;
    }
	printf("%d\n",m);
	int wlen = m;
	char rbuf[1001];
	int rlen = 0;
//4052632

	int n = wlen / 1000 + 1;
	for (int i = 0; i < n; i++) {
		//if (tcp_sock_write(tsk, wbuf + i, wlen - n) < 0)
        if(wlen >= 1000)
		    if (tcp_sock_write(tsk, wbuf + i*1000, 1000) < 0)
			    break;
        if(wlen < 1000)
		    if (tcp_sock_write(tsk, wbuf + i*1000, wlen) < 0)
			    break;
		if(wlen <= 0)
		{
			tcp_sock_write(tsk, wbuf, 0);
			break;
		}
		rlen = tcp_sock_read(tsk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		}
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			fprintf(stdout, "%s\n", rbuf);
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
		wlen = wlen - 1000;
		usleep(1000);
	}

	tcp_sock_close(tsk);

	return NULL;
}
