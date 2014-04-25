#ifndef _ENDHOST_H_
#define _ENDHOST_H_
#include "common.h"

static const struct option longOpts[] = {
	{"read", required_argument, NULL, 'r'},
	{"tcp", required_argument, NULL, 't'},
	{"udp", required_argument, NULL, 'u'},
	{"stopthresh", required_argument, NULL, 's'},
	{0,0,0,0}
};

int attack_indication = 0;
struct command_line_args
{
	char *routerfile;
	int tcpport, udpport, stopthresh;
};
FILE *fp_log;
pthread_t udp_traceback, attack_checker;
#endif
