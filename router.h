#ifndef _ROUTER_H_
#define _ROUTER_H_
#include "common.h"

static const struct option longOpts[] = {
	{"epoch", required_argument, NULL, 'e'},
	{"tcp", required_argument, NULL, 't'},
	{"udp", required_argument, NULL, 'u'},
	{"prob", required_argument, NULL, 'p'},
	{0,0,0,0}
};

struct command_line_args
{
	int udpport, tcpport;
	double prob, epoch;
};

struct ip_tcp_port
{
	int tcp_port;
	char *ip_addr;
	int thread_id;
	struct command_line_args *cmd_object;
};

struct thread_list
{
	pthread_t thread;
	int thread_id;
	struct thread_list *next;
};

struct marker_structure
{
	struct command_line_args *cmd_object;
	char *ip_address, *victim_ip_address;
	pcap_t *handle;
};

struct thread_list *thread_list_head = NULL;
FILE *fp_log;
int no_of_threads;
#endif
