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

struct router_list
{
	char router_ip[MAXIPADDRLEN];
	int frequency;
	struct router_list *next;
};

struct attacker_list
{
	char attacker_ip_addr[MAXIPADDRLEN], victim_ip_addr[MAXIPADDRLEN];
	struct router_list *routerhead;
	int no_of_routers;
	struct attacker_list *next;
};

struct attacker_list *routerAttackerHead;

void send_start_marking_msg(char *router_ip, int tcpport);
void send_stop_marking_msg(char *router_ip, int tcpport);
void receive_udp_traceback(struct command_line_args *object);
void check_for_attack(struct command_line_args *object);
void send_startMark_message_routers(struct command_line_args *object);
void send_stopMark_message_routers(struct command_line_args *object);
#endif
