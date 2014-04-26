#ifndef _TRAFFANA_H_
#define _TRAFFANA_H_

#include "common.h"
struct command_line_args
{
 	int verbose,tuple;
	float timeEpoch;
	char *interface, *readFileName, *writeFileName; 
	int pktthresh, flowthresh, srcthresh, bytethresh;
};

struct flowLinkList
{
	char *address_string;
	struct flowLinkList *next;
};

static const struct option longOpts[] = {
	{"verbose", no_argument, NULL, 'v'},
	{"read", required_argument, NULL, 'r'},
	{"int", required_argument, NULL, 'i'},
	{"time", required_argument, NULL, 'T'},
	{"write", required_argument, NULL, 'w'},
	{"track", required_argument, NULL, 'z'},
	{"p", required_argument, NULL, 'p'},
	{"b", required_argument, NULL, 'b'},
	{"f", required_argument, NULL, 'f'},
	{"s", required_argument, NULL, 's'},
	{0,0,0,0}
};


FILE *fp, *fp_log;
int total_count = 0, tcp_count = 0, udp_count = 0, icmp_count = 0, others_count = 0, total_bytes = 0;
int no_of_flows = 0, tcp_flows = 0, udp_flows = 0;
double ref_time = -1, curtime = 0;
struct flowLinkList *head = NULL;

struct srclist
{
	char src_ip_addr[MAXIPADDRLEN];
	struct srclist *next;
};
struct srcdestList
{
	char dest_ip_addr[MAXIPADDRLEN];
	struct srclist *srchead;
	int no_of_sources;
	struct srcdestList *next;
};

struct srcdestList *srcdestHead = NULL;
int max_no_sources = 0;
#endif
