/*
 * Copyright (c) 2006
 * Ningning Hu and the Carnegie Mellon University.
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author(s) may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.  
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include "setsignal.h"
#include "common.h"

#define PhaseWait	(0.3)	/* wait for next packets for 1s */
#define NoDataWait	(600)	/* wait time when there is no data coming */
#define GetPktTimeOut	(0.3)	/* wait time when there is no data coming */
#define MaxClientNum 	(64)	/* this is used for filter cmd set up */
#define MaxNoDataNum	(3)	/* number of phases allowed to be no data */

char version[] = "2.2";

struct filter_item {
	struct sockaddr_storage dst_addr, src_addr;
	char src_ip_str[NI_MAXHOST], dst_ip_str[NI_MAXHOST];
	int control_sock;
	int listen_port;
	//int listen_sock;
	int listen_sock[MAX_SOCK];
	int smax;
	int sockmax;
	fd_set rfds0;

	struct pkt_rcd_t record[MaxProbeNum];
	/* last active time */
	double pre_time;
	/* the number of packets we have filtered out for this filter */
	int count;
	/* the number of packets client should send to us */
	int probe_num;

	/* number of consecutive no data phase, 3 means dead */
	int nodata_count;
	/* working state */
	int dead;
        pthread_t thread;

	struct filter_item * next;
};
struct filter_item * filter_list = NULL;
pthread_mutex_t filter_mutex;

struct sockaddr_storage dst_addr, src_addr;
uint16 src_port, dst_port;
char src_ip_str[NI_MAXHOST], dst_ip_str[NI_MAXHOST];
int src_size, dst_size;

int probe_num = 60;
int verbose = 0;
int debug = 0;


/* usage message */
void Usage()
{
	printf("IGI/PTR-%s server usage:\n\n", version);
	printf("\tigi-server [-vd]\n\n");
	printf("\t-h\tprint this message.\n");
	printf("\t-v\tverbose mode.\n");
	printf("\t-d\tdebug mode (dump more message than the verbose mode).\n\n");
	exit(1);
}

/* make a clean exit on interrupts */
RETSIGTYPE cleanup(int signo)
{
	struct filter_item * pfilter;
	struct filter_item * pfilter_post;

	    pfilter = filter_list;
	    while (pfilter != NULL) {
		pfilter_post = pfilter->next;
		if (!(pfilter->dead))
		    close(pfilter->control_sock);
		free(pfilter);
		pfilter = pfilter_post;
	    }

  	exit(0);
}


/* get the current time */
double get_time()
{
	struct timeval tv;
	struct timezone tz;
	double cur_time; 

	if (gettimeofday(&tv, &tz) < 0) {
	    perror("get_time() fails, exit\n");
	    exit(1);
	}

	cur_time = (double)tv.tv_sec + ((double)tv.tv_usec/(double)1000000.0);
	return cur_time;
}


/* check if we have got all the packets for client's one-phase probing 	*/
/* and can send back the filter packet information 			*/
void phase_finish()
{
	/* Phase end condition:
	 * 1. get probe_num probing packets
	 * 2. no new packet after PhaseWait time
	 */

	double cur_time = get_time();
	struct filter_item * ptr;

	char msg_buf[64];
	int msg_len;
	int data_size; 
	int i;
	ssize_t send_ret; // for debug

	pthread_mutex_lock(&filter_mutex);

	for (ptr=filter_list; ptr != NULL; ptr=ptr->next) {
	    if (ptr->dead) continue;

	    if (ptr->count == 0) { 
			if (cur_time - ptr->pre_time > NoDataWait) {
				/* this is a no data phase */
				ptr->nodata_count ++;
				if (ptr->nodata_count >= MaxNoDataNum) {
					close(ptr->control_sock);
					if (verbose) {
						printf("%d no data phases, close socket with %s\n", 
							MaxNoDataNum, ptr->src_ip_str);
					}
					ptr->dead = 1;
					pthread_mutex_unlock(&filter_mutex);
					pthread_exit(NULL);
				} else {
					if (verbose) {
						printf("start sending back 0 data\n");
					}

					data_size = sizeof(struct pkt_rcd_t) * ptr->count;		
					/* send the the control information to tell how many 
					* record will be transmitted back */
					sprintf(msg_buf, "$%d$", data_size);
					msg_len = strlen(msg_buf);
#ifndef LINUX
					send_ret = send(ptr->control_sock, msg_buf, msg_len, 0);
#else
					send_ret = send(ptr->control_sock, msg_buf, msg_len, MSG_NOSIGNAL);
#endif
					if (send_ret < 0)
						perror("0. send");
			
					if (debug) {
						printf("send out msg: | %s |\n", msg_buf);
					}

					/* send back the record information */
#ifndef LINUX
					send_ret = send(ptr->control_sock, (void *)ptr->record, 
						data_size, 0);
#else /* linux */
					send_ret = send(ptr->control_sock, (void *)ptr->record, 
						data_size, MSG_NOSIGNAL);
#endif
					if (send_ret < 0)
						perror("1. send");

					ptr->pre_time = get_time();
				}
			}

			continue;
	    }

	    /* we have got some trace packets */
	    if ((ptr->count == ptr->probe_num) || 
			(cur_time - ptr->pre_time > PhaseWait)) {

			/* clear previous bad record */
			ptr->nodata_count = 0;

			if (verbose) {
				printf("start sending back data\n");
			}

			data_size = sizeof(struct pkt_rcd_t) * ptr->count;		

			/* send the the control information to tell how many record
			* will be transmitted back */
			sprintf(msg_buf, "$%d$", data_size);
			msg_len = strlen(msg_buf);
#ifndef LINUX
			send_ret = send(ptr->control_sock, msg_buf, msg_len, 0);
#else
			send_ret = send(ptr->control_sock, msg_buf, msg_len, MSG_NOSIGNAL);
#endif
			if (send_ret < 0)
				perror("2. send");
	
			if (debug) {
				printf("send out msg: | %s |\n", msg_buf);
			}
		
			/* send back the record information */
			for (i=0; i<ptr->count; i++) {
				ptr->record[i].sec = htonl(ptr->record[i].sec);
				ptr->record[i].u_sec = htonl(ptr->record[i].u_sec);
				ptr->record[i].seq = htonl(ptr->record[i].seq);
			}
#ifndef LINUX
			send_ret = send(ptr->control_sock, (void *)ptr->record, 
				data_size, 0);
#else
			send_ret = send(ptr->control_sock, (void *)ptr->record, 
				data_size, MSG_NOSIGNAL);
#endif
			if (send_ret < 0)
				perror("3. send");

			/* ready for the next phase */
			ptr->count = 0;
			ptr->pre_time = get_time();
	    }
	}

	pthread_mutex_unlock(&filter_mutex);
}


/* the main function of child process, filter probing packets from clients */
void get_packets(struct filter_item * ptr)
{
	struct sockaddr_in client_addr;
	int client_size;

        fd_set rfds;
        struct timeval tv;
	int retval, i;

	char recv_buf[4096];
	int cur_len;	
	double cur_time;

	struct pkt_rcd_t * p_record;

	if (verbose) {
	    printf("come into get_packets \n");
	}

        tv.tv_usec = 0;

	for (;;) {
		rfds = ptr->rfds0;
		tv.tv_sec = GetPktTimeOut;
		retval = select(ptr->sockmax + 1, &rfds, NULL, NULL, &tv);
		if (retval < 0) {
            perror("select");
            exit(1);
        }

		for (i = 0; i < ptr->smax; i ++) {
			if (FD_ISSET(ptr->listen_sock[i], &rfds)) { 
				client_size = sizeof(struct sockaddr);
					cur_len = recvfrom(ptr->listen_sock[i], recv_buf, 4096, 0, 
						(struct sockaddr *) &client_addr, 
						(int *) &client_size);

				p_record = &(ptr->record[ptr->count]);

				p_record->seq = recv_buf[0];
				cur_time = get_time();
				p_record->sec = (int) cur_time;
				p_record->u_sec = (int)((cur_time - p_record->sec) * 1000000);

				if (debug)
					printf("%d %d.%d \n", ptr->count, p_record->sec, p_record->u_sec);

				ptr->count ++;
				ptr->pre_time = cur_time;
			}
		}

	    phase_finish(ptr);
	}
}


/*
 * If the <src_ip, dst_ip> pair is already in the pdev list, then just 
 * update its active_time, and return the point; 
 * otherwise, create a new filter item, and initilize it
 * return the udp listening port number
 */
void update_filter_list(
		   int newsd,
		   int probe_num,
		   char * src_ip_str, 
		   char * dst_ip_str,
		   int * listening_port)
{
	struct filter_item * p, * pre;
	double cur_time;

	pthread_mutex_lock(&filter_mutex);

        /* check whether any of the filter item has been idle long
         * enough to be considered "finish", or have no data to receive */
        p = filter_list;
        pre = NULL;
        cur_time = get_time();
        while (p != NULL) {
	    if (p->dead) {
                /* delete this item */
                if (verbose) {
                    printf("delete filter item %s %s \n",
                            p->src_ip_str, p->dst_ip_str);
                }

                if (pre == NULL)
                    filter_list = filter_list->next;
                else
                    pre->next = p->next;

                free(p);

                if (pre == NULL)
                    p = filter_list;
                else
                    p = pre->next;
            }
            else {
                pre = p;
                p = p->next;
            }
        }

        /* check if src & dst ip pair already in the filter list */
        p = filter_list;
        pre = NULL;
        while (p != NULL) {
            if ((strcmp(p->src_ip_str, src_ip_str) == 0)
                && (strcmp(p->dst_ip_str, dst_ip_str) == 0)) {
                break;
            }
            else {
                pre = p;
                p = p->next;
            }
        }

        if (p != NULL) {
	    if (verbose) {
		printf("filter item already exits\n");
	    }
	    close(p->control_sock);
	    p->control_sock = newsd;
            p->pre_time = get_time();
            p->count = 0;
            p->probe_num = probe_num;
	    p->nodata_count = 0;
	    p->dead = 0;
	}
	else {
            /* for new ip pair, append in the filter_list */
	    struct sockaddr_storage my_addr;
		
	    if (verbose) {
	        printf("create a new filter item\n");
	    }
            p = (struct filter_item *)malloc(sizeof(struct filter_item));
            strcpy(p->src_ip_str, src_ip_str);
            strcpy(p->dst_ip_str, dst_ip_str);
	    p->control_sock = newsd;
            p->pre_time = get_time();
            p->count = 0;
            p->probe_num = probe_num;
            p->nodata_count = 0;
	    p->dead = 0;

		/* UDPで待ち受けるsocketを作成 */
		struct addrinfo hints, *res, *res0;
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], port[NI_MAXSERV];
		int  i, sock[MAX_SOCK], smax = 0, sockmax = -1;
		const int on = 1;
		fd_set rfd, rfd0;
		socklen_t socklen;

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		while (dst_port < END_PORT) {
			dst_port ++; // Starting port number is START_PORT + 1
			sprintf(port, "%d", dst_port);
			if (getaddrinfo(NULL, port, &hints, &res0)) {
				perror("getaddrinfo");
				exit(1);
			}
			for (res = res0; res && smax < MAX_SOCK; res = res->ai_next) {
				p->listen_sock[smax] = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
				if (p->listen_sock[smax] < 0) {
					continue;
				}
				if (p->listen_sock[smax] >= FD_SETSIZE) {
					close(p->listen_sock[smax]);
					p->listen_sock[smax] = -1;
					continue;
				}

				if (res->ai_family == AF_INET6 && 
					setsockopt(p->listen_sock[smax], IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
						perror("setsockopt");
						p->listen_sock[smax] = -1;
						continue;
					}

				if (bind(p->listen_sock[smax], res->ai_addr, res->ai_addrlen) < 0) {
					close(p->listen_sock[smax]);
					p->listen_sock[smax] = -1;
					continue;
				}
				
				if (getnameinfo(res->ai_addr, res->ai_addrlen, 
									hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
									NI_NUMERICHOST | NI_NUMERICSERV)) {
					perror("getnameinfo");
					exit(1);
				}
				printf("listen to %s %s (UDP) [sock=%d]\n", hbuf, sbuf, p->listen_sock[smax]);

				if (p->listen_sock[smax] > sockmax) {
					sockmax = p->listen_sock[smax];
				}
				smax++;
			}
			// TODO: Searching for port numbers
			break;
		}

		if (smax == 0) {
			printf("./server: no socket to open to\n");
			exit(1);
		}

		FD_ZERO(&p->rfds0);
		for (i = 0; i < smax; i ++) {
			FD_SET(p->listen_sock[i], &p->rfds0);
#ifndef LINUX
			if (fcntl(p->listen_sock[i], F_SETFL, O_NDELAY) < 0) {
#else
			if (fcntl(p->listen_sock[i], F_SETFL, FNDELAY) < 0) {
#endif
				printf("fcntl fail \n");
				exit(1);
			}
		}

		p->smax = smax;
		p->sockmax = sockmax;
		p->listen_port = dst_port;
		p->next = NULL;

		if (pre == NULL) {
		/* this is the first filter, don't need to worry about
		* pc init */
		filter_list = p;
		} else {
			pre->next = p;
		}

		pthread_create(&(p->thread), NULL, 
			(void *)&get_packets, (struct filter_item *)p);
	}

	*listening_port = p->listen_port;

	pthread_mutex_unlock(&filter_mutex);
}


/* check if there is any new client making connection */
void check_client(int newsd)
{	    
	    char msg_buf[1024];
	    int msg_len;
	    int listening_port;

	    /* waiting for "$START$%d$", for purpose of sanity check.
	     * Here, the %d is the probe_num set by probing client */
	    msg_len = 0;
	    while ((msg_len <= 7) || (msg_buf[msg_len-1] != '$')) {
		int tmp_len; 

		/* this is to accommodate a weird behavior of FreeBSD3.4 */
	        tmp_len = read(newsd, msg_buf + msg_len,
		                   sizeof(msg_buf)-msg_len);
	        if (tmp_len <= 0) continue;

	        msg_len += tmp_len;
	    }
	    msg_buf[msg_len] = 0;
	    
	    if (strncmp(msg_buf+1, "START", 5) == 0) {
			char num_str[16], *p;

			/* get out the probe_num */
			p = index(msg_buf + 7, '$');
			strncpy(num_str, msg_buf + 7, p - msg_buf - 7);
			num_str[p - msg_buf - 7] = 0;
			probe_num = atoi(num_str);
			if (verbose) {
				printf("probe_num = %d \n", probe_num);
			}
			
			update_filter_list(newsd, probe_num,
					src_ip_str, dst_ip_str,
					&listening_port);

			sprintf(msg_buf, "$READY$$%d$", listening_port);
			msg_len = strlen(msg_buf);
#ifndef LINUX
			send(newsd, msg_buf, msg_len, 0);
#else
			send(newsd, msg_buf, msg_len, MSG_NOSIGNAL);
#endif

			if (verbose) {
				printf("listening port = %d \n", listening_port);
			}
	    }
}


int main(int argc, char *argv[])
{
	struct addrinfo hints, *res, *res0;
	int i, n, opt, ls;
	int  smax = 0, sockmax = -1;
	const int on = 1;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV], port[NI_MAXSERV];
	fd_set rfd, rfd0;
	int sock[MAX_SOCK];
	struct sockaddr_storage from;
	socklen_t socklen;

	RETSIGTYPE (*oldhandler)(int);

	verbose = 0;
	while ((opt = getopt(argc, argv, "dhv")) != EOF) {
	    switch (opt) {
	    case 'd':
		debug = 1;
		break;
	    case 'v':
		verbose = 1;
		break;
	    case 'h':
	    default:
		Usage();
	    }
	}

	/* Setup signal handler for cleaning up */
	(void)setsignal(SIGTERM, cleanup);
	(void)setsignal(SIGINT, cleanup);
	if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
	    (void)setsignal(SIGHUP, oldhandler);

	memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
	
	dst_port = START_PORT;
	while (dst_port < END_PORT) {
		dst_port ++; // Starting port number is START_PORT + 1
		sprintf(port, "%d", dst_port);
		if (getaddrinfo(NULL, port, &hints, &res0)) {
			perror("getaddrinfo");
			exit(1);
		}
		for (res = res0; res && smax < MAX_SOCK; res = res->ai_next) {
			sock[smax] = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (sock[smax] < 0) {
				continue;
			}
			if (sock[smax] >= FD_SETSIZE) {
				close(sock[smax]);
				sock[smax] = -1;
				continue;
			}

			if (res->ai_family == AF_INET6 && 
				setsockopt(sock[smax], IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
					perror("setsockopt");
					sock[smax] = -1;
					continue;
				}
			
			if (bind(sock[smax], res->ai_addr, res->ai_addrlen) < 0) {
				close(sock[smax]);
				sock[smax] = -1;
				continue;
        	}

			if (listen(sock[smax], 5) < 0) {
				close(sock[smax]);
				sock[smax] = -1;
				continue;
			}
			
			if (getnameinfo(res->ai_addr, res->ai_addrlen, 
								hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
								NI_NUMERICHOST | NI_NUMERICSERV)) {
				perror("getnameinfo");
				exit(1);
			}
			printf("listen to %s %s (TCP) [sock=%d]\n", hbuf, sbuf, sock[smax]);

			if (sock[smax] > sockmax) {
				sockmax = sock[smax];
			}
			smax++;
		}
		// TODO: Searching for port numbers
		break;
	}

	if (smax == 0) {
        printf("./server: no socket to listen to\n");
        exit(1);
    }

	FD_ZERO(&rfd0);
    for (i = 0; i < smax; i ++) {
        FD_SET(sock[i], &rfd0);
    }

	pthread_mutex_init(&filter_mutex, NULL);

	while (1) {
        rfd = rfd0;
        n = select(sockmax + 1, &rfd, NULL, NULL, NULL);
        if (n < 0) {
            perror("select");
            exit(1);
        }
        for (i = 0; i < smax; i++) {
            if (FD_ISSET(sock[i], &rfd)) {
                socklen = sizeof(from);
                ls = accept(sock[i], (struct sockaddr *)&from, &socklen);
                if (ls < 0) {
                    continue;
                }

                if (getnameinfo((struct sockaddr *)&from, &socklen,
                            hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                            NI_NUMERICHOST | NI_NUMERICSERV)) {
                    perror("getnameinfo");
                    exit(1);
                }
				strncpy(src_ip_str, hbuf, sizeof(src_ip_str));
				src_port = atoi(sbuf);
				src_addr = from;

				socklen = sizeof(dst_addr);
				getsockname(ls, (struct sockaddr *)&dst_addr, &socklen);
				if (getnameinfo((struct sockaddr *)&dst_addr, &socklen,
                            hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                            NI_NUMERICHOST | NI_NUMERICSERV)) {
                    perror("getnameinfo");
                    exit(1);
                }
				strncpy(dst_ip_str, hbuf, sizeof(dst_ip_str));
				dst_port = atoi(sbuf);

				printf("\n----------------------------------\n");
				if (verbose) {
					printf("get new connection: [sock=%d] \n", ls);
					printf("src_ip_str = %s (%d) \n", src_ip_str, src_port);
					printf("dst_ip_str = %s (%d) \n", dst_ip_str, dst_port);
					printf("waiting for START msg\n");
	    		}

                check_client(ls);
            }
        }
    }

	close(sock);
}
