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
FILE *fp_log;

#endif
